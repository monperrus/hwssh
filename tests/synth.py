"""Build synthetic FIDO attestations signed by a throwaway CA, for tests."""

from __future__ import annotations

import base64
import datetime
import hashlib
import struct
import uuid
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from fido2 import cbor

from hwssh._attest import ATTEST_MAGIC, ED25519_SK, OID_FIDO_AAGUID, TrustStore

AAGUID = uuid.UUID("11111111-2222-3333-4444-555555555555")
NOW = datetime.datetime(2026, 11, 16, tzinfo=datetime.UTC)


def s(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])


def _cert(
    subject: str,
    issuer: str,
    pub: ec.EllipticCurvePublicKey,
    signer: ec.EllipticCurvePrivateKey,
    ca: bool,
    aaguid: bytes | None = None,
) -> x509.Certificate:
    b = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=365))
        .not_valid_after(NOW + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if aaguid is not None:
        b = b.add_extension(
            x509.UnrecognizedExtension(OID_FIDO_AAGUID, b"\x04\x10" + aaguid), critical=False
        )
    return b.sign(signer, hashes.SHA256())


@dataclass
class Vendor:
    root_key: ec.EllipticCurvePrivateKey
    root: x509.Certificate
    leaf_key: ec.EllipticCurvePrivateKey
    leaf: x509.Certificate

    @property
    def store(self) -> TrustStore:
        return TrustStore([self.root])


def make_vendor(name: str = "Test Root", cert_aaguid: bytes | None = AAGUID.bytes) -> Vendor:
    rk = ec.generate_private_key(ec.SECP256R1())
    root = _cert(name, name, rk.public_key(), rk, ca=True)
    lk = ec.generate_private_key(ec.SECP256R1())
    leaf = _cert("Test Attestation", name, lk.public_key(), rk, ca=False, aaguid=cert_aaguid)
    return Vendor(rk, root, lk, leaf)


@dataclass
class Enrollment:
    pubkey: str
    attestation: bytes
    challenge: bytes


def enroll(
    vendor: Vendor,
    challenge: bytes = b"c" * 32,
    flags: int = 0x45,  # UP | UV | AT
    application: str = "ssh:",
    authdata_aaguid: bytes = AAGUID.bytes,
    signed_challenge: bytes | None = None,
    attested_pub: bytes | None = None,
) -> Enrollment:
    """A synthetic `ssh-keygen -t ed25519-sk -O write-attestation` run."""
    sk = ed25519.Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    cose = cbor.encode({1: 1, 3: -8, -1: 6, -2: attested_pub or pub})
    cred_id = b"k" * 64
    authdata = (
        hashlib.sha256(application.encode()).digest()
        + bytes([flags])
        + struct.pack(">I", 0)
        + authdata_aaguid
        + struct.pack(">H", len(cred_id))
        + cred_id
        + cose
    )
    cdh = hashlib.sha256(signed_challenge if signed_challenge is not None else challenge).digest()
    sig = vendor.leaf_key.sign(authdata + cdh, ec.ECDSA(hashes.SHA256()))
    blob = (
        s(ATTEST_MAGIC)
        + s(vendor.leaf.public_bytes(serialization.Encoding.DER))
        + s(sig)
        + s(cbor.encode(authdata))
        + struct.pack(">I", 0)
        + s(b"")
    )
    keyblob = s(ED25519_SK.encode()) + s(pub) + s(application.encode())
    line = f"{ED25519_SK} {base64.b64encode(keyblob).decode()} test"
    return Enrollment(line, blob, challenge)
