"""Offline pre-check for an OCSP stapling response (RFC 6960).

Given the same unordered PEM bag used by ``/scenarios/normalize`` plus a leaf
fingerprint, a Base64 DER OCSP response and an evaluation instant, this module
decides whether the stapled response is safe to present for that leaf *without
contacting any responder*:

* **CertID binding.** The response's single CertID must name the leaf
  certificate: its serial number must equal the leaf's, and its issuer name
  hash / issuer key hash (computed under the CertID's own hash algorithm) must
  match a certificate in the bag that cryptographically signed the leaf. The
  hashes are recomputed from the DER (``issuerNameHash`` over the issuer's
  encoded distinguished name; ``issuerKeyHash`` over the subjectPublicKey BIT
  STRING content, per RFC 6960 §4.1.1), never compared against cached values.
* **Authorized responder.** The signer is chosen from the ResponderID:
  either the leaf's issuer itself, or a response certificate that is directly
  signed by that issuer, valid at the evaluation instant and carries
  ``id-kp-OCSPSigning`` (1.3.6.1.5.5.7.3.9). byName matches the signer
  certificate's subject DN; byKey matches SHA-1 of its subjectPublicKey BIT
  STRING content.
* **Signature.** The response's signature on responseData (the
  BasicOCSPResponse) is verified with the chosen signer's public key
  (RSA PKCS#1 v1.5 / RSA-PSS, ECDSA, DSA, Ed25519/Ed448).
* **Status and freshness.** responseStatus must be successful and certStatus
  must be good. producedAt must not be later than check_time plus the allowed
  skew, nextUpdate is mandatory, and check_time (with the skew on both sides)
  must fall inside [thisUpdate, nextUpdate].

Everything that fails one of those requirements returns ``eligible: false``
with a stable machine-readable ``reason``; a revoked cert additionally reports
the revocation time and CRLReason. Only the request envelope itself (bad PEM,
unknown fingerprint, non-base64 response, out-of-range skew) is a 422.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID

from .models import OcspPrecheckRequest, OcspPrecheckResult
from .normalize import (
    FINGERPRINT_RE,
    NormalizeError,
    NormalizeFingerprintIssue,
    _load_pem_bundle,
    _verify_signature,
    cert_fingerprint,
)

_RSASSA_PSS_OID = "1.2.840.113549.1.1.10"

_RESPONSE_STATUS = {
    ocsp.OCSPResponseStatus.SUCCESSFUL: "successful",
    ocsp.OCSPResponseStatus.MALFORMED_REQUEST: "malformed_request",
    ocsp.OCSPResponseStatus.INTERNAL_ERROR: "internal_error",
    ocsp.OCSPResponseStatus.TRY_LATER: "try_later",
    ocsp.OCSPResponseStatus.SIG_REQUIRED: "sig_required",
    ocsp.OCSPResponseStatus.UNAUTHORIZED: "unauthorized",
}

_CERT_STATUS = {
    ocsp.OCSPCertStatus.GOOD: "good",
    ocsp.OCSPCertStatus.REVOKED: "revoked",
    ocsp.OCSPCertStatus.UNKNOWN: "unknown",
}

_REVOCATION_REASONS = {
    x509.ReasonFlags.unspecified: "unspecified",
    x509.ReasonFlags.key_compromise: "key_compromise",
    x509.ReasonFlags.ca_compromise: "ca_compromise",
    x509.ReasonFlags.affiliation_changed: "affiliation_changed",
    x509.ReasonFlags.superseded: "superseded",
    x509.ReasonFlags.cessation_of_operation: "cessation_of_operation",
    x509.ReasonFlags.certificate_hold: "certificate_hold",
    x509.ReasonFlags.privilege_withdrawn: "privilege_withdrawn",
    x509.ReasonFlags.aa_compromise: "aa_compromise",
    x509.ReasonFlags.remove_from_crl: "remove_from_crl",
}


# ---------------------------------------------------------------------------
# DER / hashing helpers
# ---------------------------------------------------------------------------


def _der_tlv(buf: bytes, off: int) -> tuple[int, int, int]:
    """Return (tag, content_start, content_end) for one DER TLV at ``off``."""
    pos = off + 1
    length = buf[pos]
    pos += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    return buf[off], pos, pos + length


def subject_public_key_bits(cert: x509.Certificate) -> bytes:
    """The subjectPublicKey BIT STRING *content* of a certificate's SPKI.

    RFC 6960 identifies an issuer key by hashing the BIT STRING value (the
    public key itself, e.g. the uncompressed EC point or the RSAPublicKey
    structure), not the whole SubjectPublicKeyInfo wrapper.
    """
    der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    try:
        _tag, pos, _spki_end = _der_tlv(der, 0)              # SPKI SEQUENCE
        _tag, _a, alg_end = _der_tlv(der, pos)              # AlgorithmIdentifier
        tag, bits_start, bits_end = _der_tlv(der, alg_end)  # BIT STRING
        if tag != 0x03 or der[bits_start] != 0:
            raise ValueError("unexpected SubjectPublicKeyInfo encoding")
    except (IndexError, ValueError) as exc:
        raise ValueError(f"cannot extract subjectPublicKey: {exc}") from None
    return der[bits_start + 1:bits_end]


def _digest(algorithm, data: bytes) -> bytes:
    return hashlib.new(algorithm.name, data).digest()


# ---------------------------------------------------------------------------
# Time normalization
# ---------------------------------------------------------------------------


def _as_utc(value: Optional[datetime]) -> Optional[datetime]:
    """Normalize an OCSP instant to timezone-aware UTC.

    cryptography >= 42 returns aware UTC via the ``*_utc`` properties; older
    versions return naive values already expressed in UTC.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Signature verification over responseData
# ---------------------------------------------------------------------------


def _verify_ocsp_signature(response: ocsp.OCSPResponse,
                           signer: x509.Certificate,
                           ocsp_der: bytes) -> bool:
    """Verify a BasicOCSPResponse signature with the signer's public key.

    ``ocsp_der`` is the full OCSPResponse DER; it is walked for the
    RSASSA-PSS AlgorithmIdentifier parameters, which cryptography does not
    expose on the parsed OCSPResponse object.
    """
    public_key = signer.public_key()
    signature = response.signature
    tbs = response.tbs_response_bytes

    try:
        if isinstance(public_key, (ed25519.Ed25519PublicKey,
                                   getattr(ed448, "Ed448PublicKey", ()))):
            public_key.verify(signature, tbs)
        elif isinstance(public_key, rsa.RSAPublicKey):
            if response.signature_algorithm_oid.dotted_string == _RSASSA_PSS_OID:
                params = _pss_padding(ocsp_der)
                if params is None:
                    return False
                hash_algo, pss_padding = params
                public_key.verify(signature, tbs, pss_padding, hash_algo)
            else:
                public_key.verify(
                    signature, tbs, padding.PKCS1v15(),
                    response.signature_hash_algorithm,
                )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                signature, tbs, ec.ECDSA(response.signature_hash_algorithm))
        elif isinstance(public_key, dsa.DSAPublicKey):
            public_key.verify(
                signature, tbs, response.signature_hash_algorithm)
        else:
            return False
    except (InvalidSignature, UnsupportedAlgorithm, TypeError, ValueError):
        return False
    return True


# RSASSA-PSS parameter OIDs (RFC 4055)
_OID_MGF1 = "1.2.840.113549.1.1.8"
_HASH_BY_OID = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}


def _read_tlv(buf: bytes, off: int) -> tuple[int, int, int]:
    pos = off + 1
    length = buf[pos]
    pos += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    return buf[off], pos, pos + length


def _read_oid(buf: bytes, off: int) -> tuple[str, int]:
    tag, start, end = _read_tlv(buf, off)
    if tag != 0x06:
        raise ValueError("expected OID")
    body = buf[start:end]
    first = body[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in body[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts), end


def _pss_padding(ocsp_der: bytes):
    """Build (hash, PSS padding) from the BasicOCSPResponse signatureAlgorithm.

    Walks RFC 4055 RSASSA-PSS parameters: hashAlgorithm [0],
    maskGenAlgorithm [1] (MGF1, digest must agree), saltLength [2] and an
    optional trailerField [3] (must be 1). Any unrecognized or inconsistent
    encoding returns None so verification fails closed.
    """
    try:
        # OCSPResponse SEQUENCE { responseStatus ENUMERATED,
        #   responseBytes [0] EXPLICIT ResponseBytes }
        _, pos, _end = _read_tlv(ocsp_der, 0)
        _tag, _s, pos = _read_tlv(ocsp_der, pos)        # responseStatus
        tag, wrap_start, _wrap_end = _read_tlv(ocsp_der, pos)
        if tag != 0xA0:
            return None
        # [0] EXPLICIT wraps the ResponseBytes SEQUENCE:
        # { OID id-pkix-ocsp-basic, OCTET STRING BasicOCSPResponse }
        tag, rb_start, _rb_end = _read_tlv(ocsp_der, wrap_start)
        if tag != 0x30:
            return None
        _oid, qpos = _read_oid(ocsp_der, rb_start)
        tag, oct_start, oct_end = _read_tlv(ocsp_der, qpos)
        if tag != 0x04:
            return None
        basic = ocsp_der[oct_start:oct_end]
        # BasicOCSPResponse { responseData, signatureAlgorithm, BIT STRING }
        _, bpos, _bend = _read_tlv(basic, 0)
        _tag, _s, after_tbs = _read_tlv(basic, bpos)  # responseData
        tag, alg_start, alg_end = _read_tlv(basic, after_tbs)
        if tag != 0x30:
            return None
        return _pss_params(basic[alg_start:alg_end])
    except (IndexError, ValueError, KeyError):
        return None


def _pss_params(alg: bytes):
    oid, pos = _read_oid(alg, 0)
    if oid != _RSASSA_PSS_OID:
        return None
    tag, params_start, params_end = _read_tlv(alg, pos)
    if tag != 0x30:
        return None

    hash_name: Optional[str] = None
    mgf_hash_name: Optional[str] = None
    salt_length: Optional[int] = None
    q = params_start
    while q < params_end:
        tag, cs, ce = _read_tlv(alg, q)
        if tag == 0xA0:  # hashAlgorithm [0] EXPLICIT AlgorithmIdentifier
            _t, s2, _e2 = _read_tlv(alg, cs)          # inner SEQUENCE
            h_oid, _ = _read_oid(alg, s2)
            hash_name = _HASH_BY_OID.get(h_oid)
            if hash_name is None:
                return None
        elif tag == 0xA1:  # maskGenAlgorithm [1] EXPLICIT
            _t, s2, _e2 = _read_tlv(alg, cs)          # mgf AlgorithmIdentifier
            mgf_oid, mpos = _read_oid(alg, s2)
            if mgf_oid != _OID_MGF1:
                return None
            _t, s3, _e3 = _read_tlv(alg, mpos)        # MGF1 inner AlgId
            mgf_hash_name = _HASH_BY_OID.get(_read_oid(alg, s3)[0])
            if mgf_hash_name is None:
                return None
        elif tag == 0xA2:  # saltLength [2] EXPLICIT INTEGER
            t2, s2, e2 = _read_tlv(alg, cs)
            if t2 != 0x02:
                return None
            salt_length = int.from_bytes(alg[s2:e2], "big", signed=True)
        elif tag == 0xA3:  # trailerField [3] EXPLICIT INTEGER
            t2, s2, e2 = _read_tlv(alg, cs)
            if t2 != 0x02 or int.from_bytes(alg[s2:e2], "big") != 1:
                return None
        else:
            return None
        q = ce

    # RFC 4055 makes the fields technically optional with SHA-1 defaults, but
    # an OCSP staple here must pin the digest explicitly; a missing or
    # disagreeing MGF digest is rejected rather than guessed at.
    if hash_name is None or mgf_hash_name is None:
        return None
    if hash_name != mgf_hash_name:
        return None
    if salt_length is not None and salt_length < 0:
        return None

    from cryptography.hazmat.primitives import hashes

    hash_algo = {
        "sha1": hashes.SHA1, "sha256": hashes.SHA256,
        "sha384": hashes.SHA384, "sha512": hashes.SHA512,
    }[hash_name]()
    # Absent saltLength defaults to the digest length (RFC 4055).
    if salt_length is None:
        salt_length = hash_algo.digest_size
    return hash_algo, padding.PSS(
        mgf=padding.MGF1(hash_algo), salt_length=salt_length)


# ---------------------------------------------------------------------------
# Signer selection
# ---------------------------------------------------------------------------


def _has_ocsp_signing_eku(cert: x509.Certificate) -> bool:
    try:
        eku = cert.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return False
    return ExtendedKeyUsageOID.OCSP_SIGNING in eku


def _responder_matches(
    response: ocsp.OCSPResponse, cert: x509.Certificate
) -> bool:
    if response.responder_name is not None:
        return cert.subject == response.responder_name
    if response.responder_key_hash is not None:
        try:
            return hashlib.sha1(
                subject_public_key_bits(cert)).digest() \
                == response.responder_key_hash
        except ValueError:
            return False
    return False


def _select_signer(
    response: ocsp.OCSPResponse,
    issuer: x509.Certificate,
    check_time: datetime,
) -> Optional[x509.Certificate]:
    """Choose the signer authorized by the response's ResponderID.

    The issuer itself is accepted (byName on its subject DN, or byKey on its
    public key) without requiring id-kp-OCSPSigning: a CA may sign its own
    responses. Otherwise an embedded response certificate qualifies only when
    it matches the ResponderID, is directly signed by the issuer, valid at
    check_time and carries id-kp-OCSPSigning.
    """
    if _responder_matches(response, issuer):
        return issuer

    for candidate in response.certificates:
        if not _responder_matches(response, candidate):
            continue
        if not _verify_signature(candidate, issuer):
            continue
        if not _has_ocsp_signing_eku(candidate):
            continue
        if not (_as_utc(candidate.not_valid_before_utc) <= check_time
                <= _as_utc(candidate.not_valid_after_utc)):
            continue
        return candidate
    return None


# ---------------------------------------------------------------------------
# Result construction
# ---------------------------------------------------------------------------


def _successful_fields(response: ocsp.OCSPResponse) -> dict:
    """Stable echoes of a successful response, tolerating odd encodings."""
    fields: dict = {
        "produced_at": None,
        "this_update": None,
        "next_update": None,
        "revocation_time": None,
        "responder_type": None,
    }
    try:
        fields["produced_at"] = _as_utc(response.produced_at_utc)
        fields["this_update"] = _as_utc(response.this_update_utc)
        fields["next_update"] = _as_utc(response.next_update_utc)
        fields["revocation_time"] = _as_utc(response.revocation_time_utc)
        fields["responder_type"] = (
            "by_name" if response.responder_name is not None
            else "by_key" if response.responder_key_hash is not None
            else None
        )
    except ValueError:
        pass
    return fields


def _result(
    *,
    eligible: bool,
    reason: str,
    check_time: datetime,
    message: str,
    response: Optional[ocsp.OCSPResponse] = None,
    signer: Optional[x509.Certificate] = None,
    revocation_reason: Optional[str] = None,
) -> OcspPrecheckResult:
    response_status = cert_status = None
    echo: dict = {}
    if response is not None:
        response_status = _RESPONSE_STATUS.get(response.response_status)
        if response_status == "successful":
            try:
                cert_status = _CERT_STATUS.get(response.certificate_status)
            except ValueError:
                cert_status = None
            echo = _successful_fields(response)
    return OcspPrecheckResult(
        eligible=eligible,
        reason=reason,  # type: ignore[arg-type]
        check_time=check_time,
        response_status=response_status,
        cert_status=cert_status,
        produced_at=echo.get("produced_at"),
        this_update=echo.get("this_update"),
        next_update=echo.get("next_update"),
        revocation_time=echo.get("revocation_time"),
        revocation_reason=revocation_reason,
        responder_type=echo.get("responder_type"),
        signer_fingerprint=cert_fingerprint(signer) if signer else None,
        message=message,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def precheck_ocsp(req: OcspPrecheckRequest) -> OcspPrecheckResult:
    check_time = (
        req.check_time.replace(tzinfo=timezone.utc)
        if req.check_time.tzinfo is None
        else req.check_time.astimezone(timezone.utc)
    )
    skew = timedelta(seconds=req.allowed_skew_seconds)

    def fail(reason: str, message: str, **kw) -> OcspPrecheckResult:
        return _result(eligible=False, reason=reason, check_time=check_time,
                       message=message, **kw)

    # -- envelope validation (request-level 422s) ----------------------------
    leaf_fp = req.leaf_fingerprint.strip().lower()
    if not FINGERPRINT_RE.match(leaf_fp):
        raise NormalizeError(
            "invalid_fingerprint",
            "leaf_fingerprint must be a 64-character hex SHA-256 value",
            fingerprint_issues=[NormalizeFingerprintIssue(
                fingerprint=req.leaf_fingerprint,
                referred_by="leaf_fingerprint")],
        )

    certs, pem_issues = _load_pem_bundle(req.pem_certificates)
    if pem_issues:
        raise NormalizeError(
            "invalid_pem",
            "one or more PEM list elements could not be parsed",
            pem_issues=pem_issues,
        )
    if leaf_fp not in certs:
        raise NormalizeError(
            "unknown_fingerprint",
            "leaf_fingerprint does not match any certificate in the PEM bundle",
            fingerprint_issues=[NormalizeFingerprintIssue(
                fingerprint=leaf_fp, referred_by="leaf_fingerprint")],
        )

    try:
        # Tolerate the usual PEM-style line wrapping / surrounding whitespace;
        # strict validation still rejects embedded non-base64 characters.
        compact = b"".join(req.ocsp_response.encode("ascii").split())
        ocsp_der = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        raise NormalizeError(
            "invalid_ocsp_response",
            "ocsp_response must be valid Base64-encoded DER",
        )
    if not ocsp_der:
        return fail(
            "invalid_ocsp_response",
            "ocsp_response decoded to an empty byte string",
        )

    try:
        response = ocsp.load_der_ocsp_response(ocsp_der)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return fail(
            "invalid_ocsp_response",
            "the DER payload is not a parseable OCSPResponse",
        )

    # -- responseStatus -------------------------------------------------------
    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return fail(
            "response_not_successful",
            f"OCSP responseStatus is "
            f"{_RESPONSE_STATUS.get(response.response_status, 'unknown')!r}, "
            "not 'successful'; a non-success response carries no certStatus",
            response=response,
        )

    # A successful response must contain exactly one SingleResponse: a
    # TLS staple is about one certificate, so a zero- or multi-entry response
    # cannot be evaluated to a single verdict (cryptography exposes the
    # entries lazily via .responses).
    try:
        single_responses = list(response.responses)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return fail(
            "invalid_ocsp_response",
            "successful OCSP response does not contain parseable "
            "SingleResponse entries",
            response=response,
        )
    if len(single_responses) != 1:
        return fail(
            "unexpected_single_response_count",
            f"expected exactly one SingleResponse, found "
            f"{len(single_responses)}; a stapled pre-check evaluates one cert",
            response=response,
        )

    # A successful response must expose a valid BasicOCSPResponse payload.
    try:
        cert_status_name = _CERT_STATUS[response.certificate_status]
        produced_at = _as_utc(response.produced_at_utc)
        this_update = _as_utc(response.this_update_utc)
        next_update = _as_utc(response.next_update_utc)
        revocation_time = _as_utc(response.revocation_time_utc)
        revocation_flag = response.revocation_reason
        _ = response.tbs_response_bytes
        _ = response.signature
    except (ValueError, TypeError, KeyError):
        return fail(
            "invalid_ocsp_response",
            "successful OCSP response does not contain a valid "
            "BasicOCSPResponse singleResponse",
            response=response,
        )

    leaf = certs[leaf_fp]

    # -- CertID: serial number ------------------------------------------------
    if response.serial_number != leaf.serial_number:
        return fail(
            "serial_mismatch",
            f"CertID serial {response.serial_number} does not match the "
            f"leaf serial {leaf.serial_number}",
            response=response,
        )

    # -- CertID: issuer name/key hashes over a real signer of the leaf -------
    # The CertID itself carries the expected digests; recompute both from
    # each cryptographic signer of the leaf and require equality with the
    # bytes the responder put in the CertID (never with the leaf's issuer DN).
    certid_hash = response.hash_algorithm
    try:
        certid_name_hash = response.issuer_name_hash
        certid_key_hash = response.issuer_key_hash
    except ValueError:
        return fail(
            "certid_issuer_mismatch",
            "CertID uses a hash algorithm that cannot be evaluated",
            response=response,
        )

    issuer: Optional[x509.Certificate] = None
    for candidate in certs.values():
        if candidate is leaf:
            continue
        if not _verify_signature(leaf, candidate):
            continue
        try:
            if (
                _digest(certid_hash, candidate.subject.public_bytes())
                == certid_name_hash
                and _digest(certid_hash,
                            subject_public_key_bits(candidate))
                == certid_key_hash
            ):
                issuer = candidate
                break
        except (ValueError, UnsupportedAlgorithm, TypeError):
            continue
    if issuer is None:
        return fail(
            "certid_issuer_mismatch",
            "no certificate in the PEM bundle both cryptographically signed "
            "the leaf and matches the CertID issuerNameHash/issuerKeyHash",
            response=response,
        )

    # -- ResponderID -> authorized signer ------------------------------------
    signer = _select_signer(response, issuer, check_time)
    if signer is None:
        return fail(
            "responder_untrusted",
            "the ResponderID matches neither the leaf issuer nor a directly "
            "issued response certificate that is valid at check_time and "
            "carries id-kp-OCSPSigning",
            response=response,
        )

    # -- signature over BasicOCSPResponse.responseData -----------------------
    if not _verify_ocsp_signature(response, signer, ocsp_der):
        return fail(
            "invalid_signature",
            "the OCSP response signature does not verify under the selected "
            "responder certificate",
            response=response,
            signer=signer,
        )

    # -- certStatus -----------------------------------------------------------
    if cert_status_name == "revoked":
        # RFC 5280 §5.3.1: an omitted CRLReason defaults to unspecified.
        reason_name = (
            _REVOCATION_REASONS.get(revocation_flag)
            if revocation_flag is not None
            else "unspecified"
        )
        return fail(
            "certificate_revoked",
            f"certStatus is revoked (revocation time "
            f"{revocation_time.isoformat() if revocation_time else 'unknown'}"
            f", reason {reason_name})",
            response=response,
            signer=signer,
            revocation_reason=reason_name,
        )
    if cert_status_name == "unknown":
        return fail(
            "certificate_unknown",
            "certStatus is unknown: the responder does not affirm the "
            "certificate's status",
            response=response,
            signer=signer,
        )

    # -- freshness ------------------------------------------------------------
    if produced_at > check_time + skew:
        return fail(
            "produced_at_too_late",
            f"producedAt {produced_at.isoformat()} is more than "
            f"{req.allowed_skew_seconds}s after check_time "
            f"{check_time.isoformat()}",
            response=response,
            signer=signer,
        )
    if next_update is None:
        return fail(
            "missing_next_update",
            "the singleResponse omits nextUpdate, which is required for a "
            "stapled response accepted here",
            response=response,
            signer=signer,
        )
    if check_time < this_update - skew:
        return fail(
            "before_this_update",
            f"check_time {check_time.isoformat()} is more than "
            f"{req.allowed_skew_seconds}s before thisUpdate "
            f"{this_update.isoformat()}",
            response=response,
            signer=signer,
        )
    if check_time > next_update + skew:
        return fail(
            "after_next_update",
            f"check_time {check_time.isoformat()} is more than "
            f"{req.allowed_skew_seconds}s after nextUpdate "
            f"{next_update.isoformat()}",
            response=response,
            signer=signer,
        )

    return _result(
        eligible=True,
        reason="ok",
        check_time=check_time,
        message=(
            "good OCSP response signed by an authorized responder and fresh "
            f"within the {req.allowed_skew_seconds}s skew window"
        ),
        response=response,
        signer=signer,
    )
