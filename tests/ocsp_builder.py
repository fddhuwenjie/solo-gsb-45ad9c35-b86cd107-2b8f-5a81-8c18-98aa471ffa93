"""Test helper: build RFC 6960 OCSP responses with full control over times.

cryptography's OCSPResponseBuilder stamps producedAt with the wall clock at
sign time and offers no way to override it, which makes the freshness logic
(producedAt/thisUpdate/nextUpdate against a fixed check_time) untestable
deterministically. These helpers assemble BasicOCSPResponse DER directly
(ECDSA-P256 + SHA-256 signatures, the algorithm used by the test PKI) and
parse back through cryptography's loader, so the application still sees
ordinary OCSPResponse objects.
"""
from __future__ import annotations

import hashlib
import warnings
from datetime import datetime, timezone
from typing import Iterable, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp

with warnings.catch_warnings():
    warnings.simplefilter("ignore")

OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SHA1 = "1.3.14.3.2.26"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
OID_RSASSA_PSS = "1.2.840.113549.1.1.10"
OID_MGF1 = "1.2.840.113549.1.1.8"
OID_OCSP_BASIC = "1.3.6.1.5.5.7.48.1.1"

# CRLReason tag -> enum, RFC 5280 §5.3.1
_CRL_REASONS = {
    0: x509.ReasonFlags.unspecified,
    1: x509.ReasonFlags.key_compromise,
    2: x509.ReasonFlags.ca_compromise,
    3: x509.ReasonFlags.affiliation_changed,
    4: x509.ReasonFlags.superseded,
    5: x509.ReasonFlags.cessation_of_operation,
    6: x509.ReasonFlags.certificate_hold,
    8: x509.ReasonFlags.remove_from_crl,
    9: x509.ReasonFlags.privilege_withdrawn,
    10: x509.ReasonFlags.aa_compromise,
}
_REASON_CODES = {v: k for k, v in _CRL_REASONS.items()}


# ---------------------------------------------------------------------------
# Minimal DER encoders
# ---------------------------------------------------------------------------


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = []
    while n:
        out.append(n & 0xFF)
        n >>= 8
    out.reverse()
    return bytes([0x80 | len(out)]) + bytes(out)


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _seq(content: bytes) -> bytes:
    return _tlv(0x30, content)


def _octets(content: bytes) -> bytes:
    return _tlv(0x04, content)


def _encode_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for v in parts[2:]:
        if v < 0x80:
            body += bytes([v])
        else:
            chunks = [v & 0x7F]
            v >>= 7
            while v:
                chunks.append(v & 0x7F)
                v >>= 7
            for c in reversed(chunks[1:]):
                body += bytes([0x80 | c])
            body += bytes([chunks[0]])
    return _tlv(0x06, body)


def _alg_id(oid: str) -> bytes:
    return _seq(_encode_oid(oid))


def _generalized_time(value: datetime) -> bytes:
    # RFC 6960 OCSP times (thisUpdate/nextUpdate/producedAt/revocationTime)
    # are all GeneralizedTime.
    text = value.astimezone(timezone.utc).strftime("%Y%m%d%H%M%SZ")
    return _tlv(0x18, text.encode("ascii"))


def _der_tlv(buf: bytes, off: int) -> tuple[int, int, int]:
    pos = off + 1
    length = buf[pos]
    pos += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    return buf[off], pos, pos + length


def _spki_key_bits(cert: x509.Certificate) -> bytes:
    """subjectPublicKey BIT STRING content (RFC 6960 issuerKeyHash input)."""
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _, p, _ = _der_tlv(spki, 0)
    _, _, alg_end = _der_tlv(spki, p)
    tag, bits, end = _der_tlv(spki, alg_end)
    assert tag == 0x03 and spki[bits] == 0
    return spki[bits + 1:end]


# ---------------------------------------------------------------------------
# OCSP response assembly
# ---------------------------------------------------------------------------


def _cert_id(
    cert: x509.Certificate,
    issuer: x509.Certificate,
    hash_algorithm: hashes.HashAlgorithm,
    *,
    name_hash_override: Optional[bytes] = None,
    key_hash_override: Optional[bytes] = None,
    serial_override: Optional[int] = None,
) -> bytes:
    if name_hash_override is None:
        name_hash_override = hashlib.new(
            hash_algorithm.name, issuer.subject.public_bytes()).digest()
    if key_hash_override is None:
        key_hash_override = hashlib.new(
            hash_algorithm.name, _spki_key_bits(issuer)).digest()
    serial = cert.serial_number if serial_override is None else serial_override
    length = max(1, (serial.bit_length() + 7) // 8)
    serial_bytes = serial.to_bytes(length, "big")
    # DER INTEGER needs a leading 0x00 when the top bit would otherwise read
    # the value as negative (CertificateSerial is an INTEGER).
    if serial_bytes[0] & 0x80:
        serial_bytes = b"\x00" + serial_bytes
    return _seq(
        _alg_id(OID_SHA1 if hash_algorithm.name == "sha1" else OID_SHA256)
        + _octets(name_hash_override)
        + _octets(key_hash_override)
        + _tlv(0x02, serial_bytes)
    )


def build_ocsp_response(
    cert: x509.Certificate,
    issuer: x509.Certificate,
    *,
    produced_at: datetime,
    this_update: datetime,
    next_update: Optional[datetime] = None,
    status: ocsp.OCSPCertStatus = ocsp.OCSPCertStatus.GOOD,
    revocation_time: Optional[datetime] = None,
    revocation_reason: Optional[x509.ReasonFlags] = None,
    responder_name_cert: Optional[x509.Certificate] = None,
    responder_key_cert: Optional[x509.Certificate] = None,
    signer_key=None,
    extra_certs: Iterable[x509.Certificate] = (),
    hash_algorithm: Optional[hashes.HashAlgorithm] = None,
    tamper: bool = False,
    name_hash_override: Optional[bytes] = None,
    key_hash_override: Optional[bytes] = None,
    serial_override: Optional[int] = None,
    signature_mode: str = "ecdsa",
) -> bytes:
    """Assemble a successful BasicOCSPResponse and return its DER bytes.

    ``signature_mode`` selects the signer algorithm: ``ecdsa`` (P-256 +
    SHA-256), ``rsa`` (RSA PKCS#1 v1.5 + SHA-256) or ``rsa-pss``
    (RSASSA-PSS, SHA-256, MGF1-SHA-256, 32-byte salt). The signer key must be
    of the matching type.
    """
    hash_algorithm = hash_algorithm or hashes.SHA256()
    responder_name_cert = responder_name_cert or issuer
    if signer_key is None:
        raise TypeError("signer_key is required by build_ocsp_response")

    certid = _cert_id(
        cert, issuer, hash_algorithm,
        name_hash_override=name_hash_override,
        key_hash_override=key_hash_override,
        serial_override=serial_override,
    )

    if status is ocsp.OCSPCertStatus.GOOD:
        status_field = b"\x80\x00"
    elif status is ocsp.OCSPCertStatus.UNKNOWN:
        status_field = b"\x82\x00"
    else:
        revoked_info = _generalized_time(revocation_time)
        if revocation_reason is not None:
            code = _REASON_CODES[revocation_reason]
            # CRLReason [0] EXPLICIT CRLReason ENUMERATED
            revoked_info += _tlv(
                0xA0, _tlv(0x0A, bytes([code])))
        status_field = _tlv(0xA1, revoked_info)

    single = _seq(
        certid
        + status_field
        + _generalized_time(this_update)
        + (_tlv(0xA0, _generalized_time(next_update))
           if next_update is not None else b"")
    )

    if responder_key_cert is not None:
        rid = _tlv(0xA2, _octets(
            hashlib.sha1(_spki_key_bits(responder_key_cert)).digest()))
    else:
        rid = _tlv(0xA1, responder_name_cert.subject.public_bytes())

    tbs = _seq(rid + _generalized_time(produced_at) + _seq(single))

    if signature_mode == "ecdsa":
        signature = signer_key.sign(tbs, ec.ECDSA(hashes.SHA256()))
        signature_alg = _alg_id(OID_ECDSA_SHA256)
    elif signature_mode == "rsa":
        from cryptography.hazmat.primitives.asymmetric import padding as _pad

        signature = signer_key.sign(
            tbs, _pad.PKCS1v15(), hashes.SHA256())
        # sha256WithRSAEncryption (the RFC 6960 AlgorithmIdentifier form,
        # rather than rsaEncryption).
        signature_alg = _seq(_encode_oid(OID_SHA256_WITH_RSA)
                             + _tlv(0x05, b""))
    elif signature_mode == "rsa-pss":
        from cryptography.hazmat.primitives.asymmetric import padding as _pad

        # RSASSA-PSS params: sha256 [0], mgf1+sha256 [1], saltLength 32 [2].
        sha256_alg = _seq(_encode_oid(OID_SHA256) + _tlv(0x05, b""))
        mgf1 = _seq(_encode_oid(OID_MGF1) + sha256_alg)
        params = (
            _tlv(0xA0, sha256_alg)
            + _tlv(0xA1, mgf1)
            + _tlv(0xA2, _tlv(0x02, bytes([32])))
        )
        signature = signer_key.sign(
            tbs,
            _pad.PSS(mgf=_pad.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
        # AlgorithmIdentifier { OID rsaPSS, params SEQUENCE }
        signature_alg = _seq(_encode_oid(OID_RSASSA_PSS) + _seq(params))
    else:
        raise ValueError(f"unknown signature_mode {signature_mode!r}")
    if tamper:
        signature = bytes([signature[0] ^ 0xFF]) + signature[1:]

    body = tbs + signature_alg + _tlv(0x03, b"\x00" + signature)
    embedded = list(extra_certs)
    if embedded:
        body += _tlv(
            0xA0,
            _seq(b"".join(c.public_bytes(serialization.Encoding.DER)
                          for c in embedded)),
        )
    basic = _seq(body)
    response_bytes = _tlv(
        0xA0, _seq(_encode_oid(OID_OCSP_BASIC) + _octets(basic)))
    return _seq(b"\x0a\x01\x00" + response_bytes)


def build_unsuccessful(code: int) -> bytes:
    """OCSPResponse carrying only an error responseStatus enum value."""
    return _seq(_tlv(0x0A, bytes([code])))


def build_cert_id_response(
    cert: x509.Certificate,
    issuer: x509.Certificate,
    issuer_key,
    **kwargs,
) -> bytes:
    """Convenience wrapper defaulting the signer to the issuer's key."""
    return build_ocsp_response(
        cert, issuer, signer_key=issuer_key, **kwargs)
