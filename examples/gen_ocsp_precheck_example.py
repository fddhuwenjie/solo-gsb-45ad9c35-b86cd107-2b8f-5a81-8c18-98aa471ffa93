#!/usr/bin/env python3
"""Regenerate examples/ocsp_precheck_request.json from freshly built PKI.

The example is an offline stapling pre-check for the rotation target leaf:

    New Root (self-signed) -> New Intermediate -> api.example.com (target leaf)

The issuer (intermediate) signs a good, fresh OCSP response about the target
leaf with a byName ResponderID, exactly as an HTTPS origin would staple it.
``check_time`` lies inside the (thisUpdate, nextUpdate) window.

The OCSPResponse is assembled by the same deterministic DER builder the test
suite uses (cryptography cannot stamp producedAt at a fixed time), so the
example stays reproducible regardless of the regeneration wall-clock.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.ocsp_builder import build_ocsp_response  # noqa: E402

CHECK_TIME = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)
THIS_UPDATE = CHECK_TIME - timedelta(hours=1)
NEXT_UPDATE = CHECK_TIME + timedelta(days=7)
PRODUCED_AT = CHECK_TIME - timedelta(minutes=5)


def dn(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def main() -> None:
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = (
        x509.CertificateBuilder()
        .subject_name(dn("New Root CA")).issuer_name(dn("New Root CA"))
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(CHECK_TIME - timedelta(days=3650))
        .not_valid_after(CHECK_TIME + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                       critical=True)
        .sign(root_key, hashes.SHA256())
    )
    inter_key = ec.generate_private_key(ec.SECP256R1())
    inter = (
        x509.CertificateBuilder()
        .subject_name(dn("New Intermediate CA"))
        .issuer_name(dn("New Root CA"))
        .public_key(inter_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(CHECK_TIME - timedelta(days=365))
        .not_valid_after(CHECK_TIME + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                       critical=True)
        .sign(root_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(dn("api.example.com"))
        .issuer_name(dn("New Intermediate CA"))
        .public_key(leaf_key.public_key())
        .serial_number(0x00D7F1A3)
        .not_valid_before(CHECK_TIME - timedelta(days=30))
        .not_valid_after(CHECK_TIME + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("api.example.com"),
                x509.DNSName("*.svc.example.com"),
            ]),
            critical=False,
        )
        .sign(inter_key, hashes.SHA256())
    )

    # Good OCSP response signed by the direct issuer (byName), fresh window.
    ocsp_der = build_ocsp_response(
        leaf,
        inter,
        signer_key=inter_key,
        produced_at=PRODUCED_AT,
        this_update=THIS_UPDATE,
        next_update=NEXT_UPDATE,
    )

    payload = {
        "pem_certificates": [
            root.public_bytes(serialization.Encoding.PEM).decode(),
            inter.public_bytes(serialization.Encoding.PEM).decode(),
            leaf.public_bytes(serialization.Encoding.PEM).decode(),
        ],
        "leaf_fingerprint": hashlib.sha256(
            leaf.public_bytes(serialization.Encoding.DER)).hexdigest(),
        "ocsp_response": base64.b64encode(ocsp_der).decode(),
        "check_time": CHECK_TIME.isoformat().replace("+00:00", "Z"),
        "allowed_skew_seconds": 300,
    }

    out = Path(__file__).with_name("ocsp_precheck_request.json")
    out.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"wrote {out}")
    print(f"  target leaf : {payload['leaf_fingerprint']}")
    print(f"  this_update : {THIS_UPDATE.isoformat()}")
    print(f"  next_update : {NEXT_UPDATE.isoformat()}")
    print(f"  produced_at : {PRODUCED_AT.isoformat()}")


if __name__ == "__main__":
    main()
