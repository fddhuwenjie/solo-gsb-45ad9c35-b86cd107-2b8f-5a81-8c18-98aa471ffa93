"""Tests for POST /deployments/ocsp-precheck (offline OCSP staple pre-check)."""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient

from app.main import app
from tests.ocsp_builder import build_ocsp_response, build_unsuccessful

NOW = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
THIS_UPDATE = NOW - timedelta(hours=1)
NEXT_UPDATE = NOW + timedelta(days=7)
PRODUCED = NOW - timedelta(minutes=5)

client = TestClient(app)


# ---------------------------------------------------------------------------
# PKI factory
# ---------------------------------------------------------------------------


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _dn(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _root(cn="Root"):
    key = _key()
    cert = (
        x509.CertificateBuilder()
        .subject_name(_dn(cn)).issuer_name(_dn(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=3650))
        .not_valid_after(NOW + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                       critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _inter(subject_cn, issuer_cn, issuer_key, subject_key=None,
           name_constraints=None):
    subject_key = subject_key or _key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(_dn(subject_cn)).issuer_name(_dn(issuer_cn))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=365))
        .not_valid_after(NOW + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                       critical=True)
    )
    if name_constraints is not None:
        builder = builder.add_extension(name_constraints, critical=True)
    return builder.sign(issuer_key, hashes.SHA256()), subject_key


def _leaf(issuer_cn, issuer_key, *, serial=0x1234, dns_names=("svc.example.com",),
          not_before=NOW - timedelta(days=30), not_after=NOW + timedelta(days=30)):
    key = _key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(_dn("svc")).issuer_name(_dn(issuer_cn))
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before).not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
    )
    if dns_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(n) for n in dns_names]), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


def _delegated_responder(issuer_cn, issuer_key, *, cn="OCSP Responder",
                         valid_at=NOW, eku=True, subject_key=None):
    subject_key = subject_key or _key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(_dn(cn)).issuer_name(_dn(issuer_cn))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_at - timedelta(days=30))
        .not_valid_after(valid_at + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
    )
    if eku:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),
            critical=True)
    return builder.sign(issuer_key, hashes.SHA256()), subject_key


def pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def fp(cert) -> str:
    return hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def b64(der: bytes) -> str:
    return base64.b64encode(der).decode()


def make_response(leaf, issuer, issuer_key, **kwargs):
    kwargs.setdefault("produced_at", PRODUCED)
    kwargs.setdefault("this_update", THIS_UPDATE)
    kwargs.setdefault("next_update", NEXT_UPDATE)
    kwargs.setdefault("signer_key", issuer_key)
    return build_ocsp_response(leaf, issuer, **kwargs)


def precheck(bundle, leaf, response_der, *, check_time=NOW, skew=300):
    return client.post("/deployments/ocsp-precheck", json={
        "pem_certificates": [pem(c) for c in bundle],
        "leaf_fingerprint": fp(leaf),
        "ocsp_response": b64(response_der),
        "check_time": check_time.isoformat(),
        "allowed_skew_seconds": skew,
    })


# ---------------------------------------------------------------------------
# Eligible happy path
# ---------------------------------------------------------------------------


class TestEligible:
    def test_issuer_signed_good_by_name(self):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        r = precheck([root, leaf], leaf,
                     make_response(leaf, root, root_key))
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["eligible"] is True
        assert body["reason"] == "ok"
        assert body["response_status"] == "successful"
        assert body["cert_status"] == "good"
        assert body["responder_type"] == "by_name"
        assert body["signer_fingerprint"] == fp(root)
        assert body["produced_at"] == PRODUCED.isoformat().replace("+00:00", "Z")
        assert body["this_update"] == THIS_UPDATE.isoformat().replace("+00:00", "Z")
        assert body["next_update"] == NEXT_UPDATE.isoformat().replace("+00:00", "Z")
        assert body["revocation_time"] is None
        assert body["revocation_reason"] is None

    def test_intermediate_is_accepted_as_issuer(self):
        root, root_key = _root()
        inter, inter_key = _inter("Inter", "Root", root_key)
        leaf = _leaf("Inter", inter_key)
        # The bundle need not even contain the trust root: CertID identifies
        # the direct issuer, and chain reconstruction is not part of this
        # offline check.
        r = precheck([inter, leaf], leaf,
                     make_response(leaf, inter, inter_key))
        assert r.status_code == 200
        body = r.json()
        assert body["eligible"] is True
        assert body["signer_fingerprint"] == fp(inter)

    def test_issuer_by_key_responder_id(self):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        der = make_response(leaf, root, root_key, responder_key_cert=root)
        r = precheck([root, leaf], leaf, der)
        assert r.status_code == 200
        body = r.json()
        assert body["eligible"] is True
        assert body["responder_type"] == "by_key"

    def test_delegated_responder_by_name(self):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        rcert, rkey = _delegated_responder("Root", root_key)
        der = make_response(
            leaf, root, root_key,
            signer_key=rkey, responder_name_cert=rcert,
            extra_certs=[rcert])
        r = precheck([root, leaf, rcert], leaf, der)
        assert r.status_code == 200
        body = r.json()
        assert body["eligible"] is True
        assert body["signer_fingerprint"] == fp(rcert)

    def test_delegated_responder_by_key(self):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        rcert, rkey = _delegated_responder("Root", root_key)
        der = make_response(
            leaf, root, root_key,
            signer_key=rkey, responder_key_cert=rcert,
            extra_certs=[rcert])
        r = precheck([root, leaf, rcert], leaf, der)
        assert r.status_code == 200
        assert r.json()["eligible"] is True

    def test_sha1_certid_hash_accepted(self):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        der = make_response(leaf, root, root_key,
                            hash_algorithm=hashes.SHA1())
        r = precheck([root, leaf], leaf, der)
        assert r.status_code == 200
        assert r.json()["eligible"] is True


# ---------------------------------------------------------------------------
# Alternative signer key types
# ---------------------------------------------------------------------------


def _rsa_chain():
    from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod

    root_key = rsa_mod.generate_private_key(
        public_exponent=65537, key_size=2048)
    root = (
        x509.CertificateBuilder()
        .subject_name(_dn("Root")).issuer_name(_dn("Root"))
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=3650))
        .not_valid_after(NOW + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                       critical=True)
        .sign(root_key, hashes.SHA256())
    )
    leaf_key = rsa_mod.generate_private_key(
        public_exponent=65537, key_size=2048)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(_dn("svc")).issuer_name(_dn("Root"))
        .public_key(leaf_key.public_key())
        .serial_number(0x1234)
        .not_valid_before(NOW - timedelta(days=30))
        .not_valid_after(NOW + timedelta(days=30))
        .sign(root_key, hashes.SHA256())
    )
    return root, root_key, leaf


class TestRsaSignatures:
    def test_rsa_pkcs1_signature_accepted(self):
        root, root_key, leaf = _rsa_chain()
        der = make_response(leaf, root, root_key, signature_mode="rsa")
        r = precheck([root, leaf], leaf, der)
        assert r.status_code == 200
        body = r.json()
        assert body["eligible"] is True
        assert body["signer_fingerprint"] == fp(root)

    def test_rsa_pss_signature_accepted(self):
        root, root_key, leaf = _rsa_chain()
        der = make_response(leaf, root, root_key, signature_mode="rsa-pss")
        r = precheck([root, leaf], leaf, der)
        assert r.status_code == 200
        body = r.json()
        assert body["eligible"] is True
        assert body["reason"] == "ok"

    def test_rsa_pss_tampered_signature_rejected(self):
        root, root_key, leaf = _rsa_chain()
        der = make_response(leaf, root, root_key,
                            signature_mode="rsa-pss", tamper=True)
        r = precheck([root, leaf], leaf, der)
        assert r.status_code == 200
        body = r.json()
        assert body["reason"] == "invalid_signature"
        assert body["signer_fingerprint"] == fp(root)


class TestEd25519:
    def test_ed25519_signature_accepted(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519

        root_key = ed25519.Ed25519PrivateKey.generate()
        root = (
            x509.CertificateBuilder()
            .subject_name(_dn("Root")).issuer_name(_dn("Root"))
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - timedelta(days=3650))
            .not_valid_after(NOW + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                           critical=True)
            .sign(root_key, None)
        )
        leaf_key = ed25519.Ed25519PrivateKey.generate()
        leaf = (
            x509.CertificateBuilder()
            .subject_name(_dn("svc")).issuer_name(_dn("Root"))
            .public_key(leaf_key.public_key())
            .serial_number(0x1234)
            .not_valid_before(NOW - timedelta(days=30))
            .not_valid_after(NOW + timedelta(days=30))
            .sign(root_key, None)
        )
        # cryptography builds Ed25519 OCSP responses directly; producedAt is
        # stamped at wall-clock, so anchor check_time to real now.
        real_now = datetime.now(timezone.utc)
        response = (
            ocsp.OCSPResponseBuilder()
            .add_response(leaf, root, hashes.SHA256(),
                          ocsp.OCSPCertStatus.GOOD,
                          real_now - timedelta(hours=1),
                          real_now + timedelta(days=7), None, None)
            .responder_id(ocsp.OCSPResponderEncoding.NAME, root)
            .sign(root_key, None)
        )
        der = response.public_bytes(serialization.Encoding.DER)
        r = precheck([root, leaf], leaf, der, check_time=real_now)
        assert r.status_code == 200
        assert r.json()["eligible"] is True
        assert r.json()["signer_fingerprint"] == fp(root)


# ---------------------------------------------------------------------------
# CertID binding
# ---------------------------------------------------------------------------


class TestCertId:
    def test_serial_mismatch(self):
        root, root_key = _root()
        leaf = _leaf("Root", root_key, serial=0x1234)
        other = _leaf("Root", root_key, serial=0x9999)
        # Response is about `leaf`, but the request names `other`.
        der = make_response(leaf, root, root_key)
        r = precheck([root, other], other, der)
        assert r.status_code == 200
        body = r.json()
        assert body["eligible"] is False
        assert body["reason"] == "serial_mismatch"
        assert body["signer_fingerprint"] is None

    def test_issuer_name_hash_mismatch(self):
        # The CertID issuerNameHash names a DN that no signer of the leaf has:
        # the real issuer signed the leaf but its subject hashes differently.
        root, root_key = _root("Real Root")
        leaf = _leaf("Real Root", root_key)
        bogus_name_digest = hashlib.sha256(b"CN=Bogus Root").digest()
        der = build_ocsp_response(
            leaf, root, signer_key=root_key,
            produced_at=PRODUCED, this_update=THIS_UPDATE,
            next_update=NEXT_UPDATE,
            name_hash_override=bogus_name_digest)
        r = precheck([root, leaf], leaf, der)
        assert r.status_code == 200
        assert r.json()["reason"] == "certid_issuer_mismatch"

    def test_issuer_key_hash_mismatch(self):
        # CertID carries the issuer's real DN but a key hash that matches no
        # certificate that signed the leaf.
        root, root_key = _root("Root")
        leaf = _leaf("Root", root_key)
        other_key = _key()
        same_dn = (
            x509.CertificateBuilder()
            .subject_name(_dn("Root")).issuer_name(_dn("Root"))
            .public_key(other_key.public_key())
            .serial_number(8)
            .not_valid_before(NOW - timedelta(days=3650))
            .not_valid_after(NOW + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                           critical=True)
            .sign(other_key, hashes.SHA256())
        )
        bogus_key_digest = hashlib.sha256(b"\x04" + b"bogus-key-bits").digest()
        der = build_ocsp_response(
            leaf, root, signer_key=root_key,
            produced_at=PRODUCED, this_update=THIS_UPDATE,
            next_update=NEXT_UPDATE,
            key_hash_override=bogus_key_digest)
        r = precheck([root, same_dn, leaf], leaf, der)
        assert r.status_code == 200
        assert r.json()["reason"] == "certid_issuer_mismatch"

    def test_issuer_absent_from_bundle(self):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        unrelated, unrelated_key = _root("Unrelated")
        der = make_response(leaf, root, root_key)
        r = precheck([unrelated, leaf], leaf, der)
        assert r.status_code == 200
        assert r.json()["reason"] == "certid_issuer_mismatch"


# ---------------------------------------------------------------------------
# Responder authorization
# ---------------------------------------------------------------------------


class TestResponderSelection:
    def test_responder_name_matches_nobody(self):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        stranger, skey = _delegated_responder("Root", root_key,
                                              cn="Some Other Responder")
        # Response signed by the issuer, but its ResponderID advertises a name
        # matching neither the issuer nor any embedded certificate.
        der = build_ocsp_response(
            leaf, root, signer_key=root_key,
            responder_name_cert=stranger,
            produced_at=PRODUCED, this_update=THIS_UPDATE,
            next_update=NEXT_UPDATE)
        r = precheck([root, leaf, stranger], leaf, der)
        assert r.status_code == 200
        assert r.json()["reason"] == "responder_untrusted"

    def test_delegated_cert_missing_from_response(self):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        rcert, rkey = _delegated_responder("Root", root_key)
        der = make_response(
            leaf, root, root_key,
            signer_key=rkey, responder_name_cert=rcert)
        # The responder cert exists in the bag but is not embedded.
        r = precheck([root, leaf, rcert], leaf, der)
        assert r.status_code == 200
        assert r.json()["reason"] == "responder_untrusted"

    def test_delegated_cert_without_eku_rejected(self):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        rcert, rkey = _delegated_responder("Root", root_key, eku=False)
        der = make_response(
            leaf, root, root_key,
            signer_key=rkey, responder_name_cert=rcert,
            extra_certs=[rcert])
        r = precheck([root, leaf, rcert], leaf, der)
        assert r.status_code == 200
        assert r.json()["reason"] == "responder_untrusted"

    def test_expired_delegated_cert_rejected(self):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        rcert, rkey = _delegated_responder("Root", root_key)
        # Rewrap the responder cert so it is already expired at check_time.
        expired, expired_key = _delegated_responder(
            "Root", root_key, cn="OCSP Responder",
            valid_at=NOW - timedelta(days=180))
        der = make_response(
            leaf, root, root_key,
            signer_key=expired_key, responder_name_cert=expired,
            extra_certs=[expired])
        r = precheck([root, leaf, expired], leaf, der)
        assert r.status_code == 200
        assert r.json()["reason"] == "responder_untrusted"

    def test_delegated_cert_not_issued_by_leaf_issuer(self):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        _, alien_key = _root("Alien Root")
        rcert, rkey = _delegated_responder("Alien Root", alien_key)
        der = make_response(
            leaf, root, root_key,
            signer_key=rkey, responder_name_cert=rcert,
            extra_certs=[rcert])
        r = precheck([root, leaf, rcert], leaf, der)
        assert r.status_code == 200
        assert r.json()["reason"] == "responder_untrusted"

    def test_delegated_cert_valid_within_skew_boundary(self):
        # The delegated cert's validity is evaluated at check_time itself;
        # skew tolerance does not extend the signer cert's validity.
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        key2 = _key()
        not_after = NOW - timedelta(seconds=1)
        rcert = (
            x509.CertificateBuilder()
            .subject_name(_dn("OCSP Responder")).issuer_name(_dn("Root"))
            .public_key(key2.public_key()).serial_number(55)
            .not_valid_before(NOW - timedelta(days=30))
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),
                           critical=True)
            .sign(root_key, hashes.SHA256())
        )
        der = make_response(
            leaf, root, root_key,
            signer_key=key2, responder_name_cert=rcert,
            extra_certs=[rcert])
        r = precheck([root, leaf, rcert], leaf, der, skew=300)
        assert r.status_code == 200
        assert r.json()["reason"] == "responder_untrusted"


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------


class TestSignature:
    def test_tampered_issuer_signature_rejected(self):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        der = make_response(leaf, root, root_key, tamper=True)
        r = precheck([root, leaf], leaf, der)
        assert r.status_code == 200
        body = r.json()
        assert body["reason"] == "invalid_signature"
        # The issuer was the chosen responder, so its fingerprint is reported
        # even though its signature over responseData failed.
        assert body["signer_fingerprint"] == fp(root)

    def test_embedded_cert_must_carry_the_signing_key(self):
        # The byName ResponderID selects an embedded, valid id-kp-OCSPSigning
        # certificate issued by the leaf's issuer, but the response was made
        # by a different private key: the signature must not verify under the
        # certificate the ResponderID resolved to.
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        rcert, rkey = _delegated_responder("Root", root_key)
        alien_key = _key()
        # Sign with a key unrelated to rcert; responder name still resolves
        # to the embedded rcert (which does carry id-kp-OCSPSigning).
        der = build_ocsp_response(
            leaf, root, signer_key=alien_key,
            responder_name_cert=rcert, extra_certs=[rcert],
            produced_at=PRODUCED, this_update=THIS_UPDATE,
            next_update=NEXT_UPDATE)
        r = precheck([root, leaf, rcert], leaf, der)
        assert r.status_code == 200
        body = r.json()
        assert body["reason"] == "invalid_signature"
        assert body["signer_fingerprint"] == fp(rcert)

    def test_delegated_tampered_signature_names_its_signer(self):
        # When the ResponderID selects the embedded cert but its signature
        # fails, the diagnostic still identifies which cert was selected.
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        rcert, rkey = _delegated_responder("Root", root_key)
        der = bytearray(make_response(
            leaf, root, root_key,
            signer_key=rkey, responder_name_cert=rcert,
            extra_certs=[rcert]))
        # Flip a byte inside the embedded certificate so the parsed cert B no
        # longer matches the signed tbs material; simpler: flip the signature
        # would make signer still rcert, which is what we want to assert.
        der = bytes(der)
        # tamper=True flips the first signature byte while keeping the certs
        der = make_response(
            leaf, root, root_key,
            signer_key=rkey, responder_name_cert=rcert,
            extra_certs=[rcert], tamper=True)
        r = precheck([root, leaf, rcert], leaf, der)
        assert r.status_code == 200
        body = r.json()
        assert body["reason"] == "invalid_signature"
        assert body["signer_fingerprint"] == fp(rcert)


# ---------------------------------------------------------------------------
# certStatus
# ---------------------------------------------------------------------------


class TestCertStatus:
    @pytest.mark.parametrize("reason_flag,reason_name", [
        (x509.ReasonFlags.key_compromise, "key_compromise"),
        (x509.ReasonFlags.ca_compromise, "ca_compromise"),
        (x509.ReasonFlags.affiliation_changed, "affiliation_changed"),
        (x509.ReasonFlags.superseded, "superseded"),
        (x509.ReasonFlags.cessation_of_operation, "cessation_of_operation"),
        (x509.ReasonFlags.certificate_hold, "certificate_hold"),
        (x509.ReasonFlags.privilege_withdrawn, "privilege_withdrawn"),
        (x509.ReasonFlags.remove_from_crl, "remove_from_crl"),
        (x509.ReasonFlags.aa_compromise, "aa_compromise"),
        (x509.ReasonFlags.unspecified, "unspecified"),
    ])
    def test_revoked_reports_time_and_reason(self, reason_flag, reason_name):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        revocation_time = NOW - timedelta(days=2, hours=3)
        der = make_response(
            leaf, root, root_key,
            status=ocsp.OCSPCertStatus.REVOKED,
            revocation_time=revocation_time,
            revocation_reason=reason_flag)
        r = precheck([root, leaf], leaf, der)
        assert r.status_code == 200
        body = r.json()
        assert body["eligible"] is False
        assert body["reason"] == "certificate_revoked"
        assert body["cert_status"] == "revoked"
        assert body["revocation_reason"] == reason_name
        expected = revocation_time.isoformat().replace("+00:00", "Z")
        assert body["revocation_time"] == expected
        assert reason_name in body["message"]

    def test_revoked_without_reason_defaults_unspecified(self):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        der = make_response(
            leaf, root, root_key,
            status=ocsp.OCSPCertStatus.REVOKED,
            revocation_time=NOW - timedelta(days=1),
            revocation_reason=None)
        r = precheck([root, leaf], leaf, der)
        body = r.json()
        assert body["reason"] == "certificate_revoked"
        assert body["revocation_reason"] == "unspecified"

    def test_unknown_status(self):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        der = make_response(leaf, root, root_key,
                            status=ocsp.OCSPCertStatus.UNKNOWN)
        r = precheck([root, leaf], leaf, der)
        body = r.json()
        assert body["eligible"] is False
        assert body["reason"] == "certificate_unknown"
        assert body["cert_status"] == "unknown"
        assert body["signer_fingerprint"] == fp(root)


# ---------------------------------------------------------------------------
# responseStatus
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("code,name", [
    (1, "malformed_request"),
    (2, "internal_error"),
    (3, "try_later"),
    (5, "sig_required"),
    (6, "unauthorized"),
])
def test_non_successful_response(code, name):
    root, root_key = _root()
    leaf = _leaf("Root", root_key)
    r = precheck([root, leaf], leaf, build_unsuccessful(code))
    assert r.status_code == 200
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "response_not_successful"
    assert body["response_status"] == name
    assert body["cert_status"] is None
    assert body["produced_at"] is None
    assert body["responder_type"] is None
    assert body["signer_fingerprint"] is None


# ---------------------------------------------------------------------------
# Freshness
# ---------------------------------------------------------------------------


class TestFreshness:
    def test_ok_inside_window(self):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        r = precheck([root, leaf], leaf, make_response(leaf, root, root_key))
        assert r.json()["eligible"] is True

    def test_produced_at_too_late(self):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        der = make_response(
            leaf, root, root_key, produced_at=NOW + timedelta(seconds=301))
        r = precheck([root, leaf], leaf, der, skew=300)
        body = r.json()
        assert body["reason"] == "produced_at_too_late"
        assert body["signer_fingerprint"] == fp(root)

    def test_produced_at_boundary_accepted(self):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        der = make_response(
            leaf, root, root_key, produced_at=NOW + timedelta(seconds=300))
        r = precheck([root, leaf], leaf, der, skew=300)
        assert r.json()["reason"] == "ok"

    def test_missing_next_update(self):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        der = make_response(
            leaf, root, root_key,
            produced_at=PRODUCED, this_update=THIS_UPDATE, next_update=None)
        r = precheck([root, leaf], leaf, der)
        assert r.json()["reason"] == "missing_next_update"

    def test_before_this_update_outside_skew(self):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        der = make_response(
            leaf, root, root_key, this_update=NOW + timedelta(seconds=301))
        r = precheck([root, leaf], leaf, der, skew=300)
        assert r.json()["reason"] == "before_this_update"

    def test_before_this_update_within_skew_accepted(self):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        der = make_response(
            leaf, root, root_key, this_update=NOW + timedelta(seconds=300))
        r = precheck([root, leaf], leaf, der, skew=300)
        assert r.json()["reason"] == "ok"

    def test_after_next_update_outside_skew(self):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        der = make_response(
            leaf, root, root_key, next_update=NOW - timedelta(seconds=301))
        r = precheck([root, leaf], leaf, der, skew=300, check_time=NOW)
        assert r.json()["reason"] == "after_next_update"

    def test_after_next_update_within_skew_accepted(self):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        der = make_response(
            leaf, root, root_key, next_update=NOW - timedelta(seconds=300))
        r = precheck([root, leaf], leaf, der, skew=300)
        assert r.json()["reason"] == "ok"

    def test_zero_skew_uses_exact_window(self):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        der = make_response(
            leaf, root, root_key, this_update=NOW + timedelta(seconds=1))
        r = precheck([root, leaf], leaf, der, skew=0)
        assert r.json()["reason"] == "before_this_update"

    def test_old_produced_at_in_the_past_is_fine(self):
        # Only "producedAt no later than check_time + skew" is constrained;
        # an old producedAt does not by itself invalidate the response.
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        der = make_response(
            leaf, root, root_key,
            produced_at=NOW - timedelta(days=30))
        r = precheck([root, leaf], leaf, der)
        assert r.json()["reason"] == "ok"


# ---------------------------------------------------------------------------
# Malformed / unparseable payloads (200, stable reason)
# ---------------------------------------------------------------------------


class TestMalformed:
    def test_garbage_der(self):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        r = precheck([root, leaf], leaf, b"not a response")
        assert r.status_code == 200
        body = r.json()
        assert body["eligible"] is False
        assert body["reason"] == "invalid_ocsp_response"
        assert body["response_status"] is None

    def test_multiple_single_responses_rejected(self):
        # A staple must be about exactly one certificate; a response carrying
        # two SingleResponses cannot yield a single verdict.
        from tests.ocsp_builder import (
            _alg_id, _cert_id, _encode_oid, _generalized_time, _octets,
            _seq, _tlv, OID_ECDSA_SHA256, OID_OCSP_BASIC,
        )

        root, root_key = _root()
        leaf = _leaf("Root", root_key, serial=0x1234)
        other = _leaf("Root", root_key, serial=0x5678)

        def single(cert):
            return _seq(
                _cert_id(cert, root, hashes.SHA256())
                + b"\x80\x00"
                + _generalized_time(THIS_UPDATE)
                + _tlv(0xA0, _generalized_time(NEXT_UPDATE))
            )

        rid = _tlv(0xA1, root.subject.public_bytes())
        tbs = _seq(
            rid
            + _generalized_time(PRODUCED)
            + _seq(single(leaf) + single(other))
        )
        signature = root_key.sign(tbs, ec.ECDSA(hashes.SHA256()))
        basic = _seq(
            tbs
            + _alg_id(OID_ECDSA_SHA256)
            + _tlv(0x03, b"\x00" + signature)
        )
        der = _seq(
            b"\x0a\x01\x00"
            + _tlv(0xA0, _seq(_encode_oid(OID_OCSP_BASIC)
                              + _octets(basic)))
        )
        r = precheck([root, leaf, other], leaf, der)
        assert r.status_code == 200
        body = r.json()
        assert body["reason"] == "unexpected_single_response_count"
        assert body["response_status"] == "successful"

    def test_der_of_an_x509_certificate(self):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        cert_der = root.public_bytes(serialization.Encoding.DER)
        r = precheck([root, leaf], leaf, cert_der)
        assert r.status_code == 200
        assert r.json()["reason"] == "invalid_ocsp_response"

    def test_base64_with_line_wrapping_accepted(self):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        der = make_response(leaf, root, root_key)
        wrapped = "\n".join(
            b64(der)[i:i + 64] for i in range(0, len(b64(der)), 64))
        r = client.post("/deployments/ocsp-precheck", json={
            "pem_certificates": [pem(root), pem(leaf)],
            "leaf_fingerprint": fp(leaf),
            "ocsp_response": wrapped,
            "check_time": NOW.isoformat(),
            "allowed_skew_seconds": 300,
        })
        assert r.status_code == 200
        assert r.json()["reason"] == "ok"


# ---------------------------------------------------------------------------
# Request envelope 422s
# ---------------------------------------------------------------------------


class Test422:
    def _payload(self, **overrides):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        payload = {
            "pem_certificates": [pem(root), pem(leaf)],
            "leaf_fingerprint": fp(leaf),
            "ocsp_response": b64(make_response(leaf, root, root_key)),
            "check_time": NOW.isoformat(),
            "allowed_skew_seconds": 300,
        }
        payload.update(overrides)
        return payload

    def test_invalid_pem(self):
        payload = self._payload(pem_certificates=["nonsense"])
        r = client.post("/deployments/ocsp-precheck", json=payload)
        assert r.status_code == 422
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_pem"
        assert detail["pem_issues"][0]["index"] == 0

    def test_bad_fingerprint_format(self):
        r = client.post("/deployments/ocsp-precheck",
                        json=self._payload(leaf_fingerprint="zz" + "0" * 62))
        assert r.status_code == 422

    def test_unknown_fingerprint(self):
        r = client.post("/deployments/ocsp-precheck",
                        json=self._payload(leaf_fingerprint="ab" * 32))
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "unknown_fingerprint"

    def test_non_base64_response(self):
        r = client.post("/deployments/ocsp-precheck",
                        json=self._payload(ocsp_response="not base64!!"))
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_ocsp_response"

    @pytest.mark.parametrize("skew", [301, -1, 10_000])
    def test_skew_out_of_range(self, skew):
        r = client.post("/deployments/ocsp-precheck",
                        json=self._payload(allowed_skew_seconds=skew))
        assert r.status_code == 422

    def test_missing_check_time(self):
        payload = self._payload()
        del payload["check_time"]
        r = client.post("/deployments/ocsp-precheck", json=payload)
        assert r.status_code == 422

    def test_naive_check_time_treated_as_utc(self):
        r = client.post("/deployments/ocsp-precheck", json=self._payload(
            check_time=NOW.replace(tzinfo=None).isoformat()))
        assert r.status_code == 200
        body = r.json()
        assert body["check_time"] == NOW.isoformat().replace("+00:00", "Z")

    def test_check_time_with_offset_normalized_to_utc(self):
        # NOW expressed in UTC+9: the same instant, normalized for output.
        local = NOW.astimezone(timezone(timedelta(hours=9))).isoformat()
        r = client.post("/deployments/ocsp-precheck",
                        json=self._payload(check_time=local))
        assert r.status_code == 200
        body = r.json()
        assert body["reason"] == "ok"
        assert body["check_time"] == NOW.isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Reason precedence: signature/status checks run before freshness
# ---------------------------------------------------------------------------


class TestReasonPrecedence:
    def test_revoked_takes_precedence_over_freshness_problem(self):
        # certStatus is checked before freshness; a revoked response that is
        # also stale reports the revocation.
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        der = make_response(
            leaf, root, root_key,
            status=ocsp.OCSPCertStatus.REVOKED,
            revocation_time=NOW - timedelta(days=2),
            next_update=NOW - timedelta(days=10))
        r = precheck([root, leaf], leaf, der)
        assert r.json()["reason"] == "certificate_revoked"

    def test_signature_failure_precedes_status(self):
        root, root_key = _root()
        leaf = _leaf("Root", root_key)
        der = make_response(
            leaf, root, root_key,
            status=ocsp.OCSPCertStatus.REVOKED,
            revocation_time=NOW - timedelta(days=2),
            tamper=True)
        r = precheck([root, leaf], leaf, der)
        assert r.json()["reason"] == "invalid_signature"
