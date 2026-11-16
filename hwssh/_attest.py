"""Verify an OpenSSH FIDO attestation (`ssh-keygen -O write-attestation`).

A key is accepted only if all of these hold:
- the attestation certificate chains to a pinned vendor root (via pinned intermediates);
- the attestation signature covers authData || SHA256(challenge);
- the credential public key in authData is the SSH public key, for the same application;
- the user-presence flag is set (and user verification, if required);
- the AAGUID in the certificate, when present, matches the one in authData.

`sk-*` key types by themselves prove nothing: any software can act as a security key
through SSH_SK_PROVIDER. The attestation is the only evidence of hardware.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import struct
import uuid
from dataclasses import dataclass, field
from importlib import resources

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from fido2 import cbor
from fido2.webauthn import AuthenticatorData

ATTEST_MAGIC = b"ssh-sk-attest-v01"
ED25519_SK = "sk-ssh-ed25519@openssh.com"
ECDSA_SK = "sk-ecdsa-sha2-nistp256@openssh.com"
SK_KEY_TYPES = (ED25519_SK, ECDSA_SK)
OID_FIDO_AAGUID = x509.ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")
MAX_CHAIN = 5


class AttestationError(Exception):
    """The key is not proven to live in trusted hardware."""


@dataclass(frozen=True)
class TrustStore:
    roots: list[x509.Certificate]
    intermediates: list[x509.Certificate] = field(default_factory=list)

    @classmethod
    def builtin(cls) -> TrustStore:
        roots: list[x509.Certificate] = []
        inter: list[x509.Certificate] = []
        for f in resources.files("hwssh.roots").iterdir():
            if f.name.endswith("-roots.pem"):
                roots += x509.load_pem_x509_certificates(f.read_bytes())
            elif f.name.endswith("-intermediates.pem"):
                inter += x509.load_pem_x509_certificates(f.read_bytes())
        return cls(roots, inter)


@dataclass(frozen=True)
class SshSkKey:
    key_type: str
    public: bytes  # ed25519: 32 raw bytes; ecdsa: uncompressed SEC1 point
    application: str
    blob: bytes

    @property
    def fingerprint(self) -> str:
        digest = hashlib.sha256(self.blob).digest()
        return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")

    def openssh(self) -> str:
        return f"{self.key_type} {base64.b64encode(self.blob).decode()}"


@dataclass(frozen=True)
class VerifiedKey:
    key: SshSkKey
    aaguid: str
    chain: list[str]  # subject CNs, leaf first, root last
    user_verified: bool


def _read_string(buf: bytes, off: int) -> tuple[bytes, int]:
    if off + 4 > len(buf):
        raise AttestationError("truncated SSH string length")
    (n,) = struct.unpack(">I", buf[off : off + 4])
    end = off + 4 + n
    if end > len(buf):
        raise AttestationError("truncated SSH string")
    return buf[off + 4 : end], end


def parse_sk_public_key(text: str) -> SshSkKey:
    """Parse an OpenSSH `sk-*` public key line (as in id_*_sk.pub)."""
    parts = text.split()
    if len(parts) < 2 or parts[0] not in SK_KEY_TYPES:
        raise AttestationError(f"not a FIDO SSH key type: {parts[0] if parts else '(empty)'}")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except ValueError as e:
        raise AttestationError(f"bad base64 in public key: {e}") from e
    ktype, off = _read_string(blob, 0)
    if ktype.decode() != parts[0]:
        raise AttestationError("key type in blob differs from key line")
    if parts[0] == ECDSA_SK:
        curve, off = _read_string(blob, off)
        if curve != b"nistp256":
            raise AttestationError(f"unsupported curve {curve!r}")
    public, off = _read_string(blob, off)
    app, off = _read_string(blob, off)
    if off != len(blob):
        raise AttestationError("trailing bytes in public key blob")
    return SshSkKey(parts[0], public, app.decode(), blob)


def parse_attestation(blob: bytes) -> tuple[bytes, bytes, bytes]:
    """Return (attestation certificate DER, signature, raw authenticator data)."""
    magic, off = _read_string(blob, 0)
    if magic != ATTEST_MAGIC:
        raise AttestationError(f"unknown attestation format {magic[:32]!r}")
    cert, off = _read_string(blob, off)
    sig, off = _read_string(blob, off)
    authdata, off = _read_string(blob, off)
    if not cert:
        raise AttestationError("no attestation certificate (self or none attestation)")
    # OpenSSH stores authData wrapped in a CBOR byte string.
    try:
        decoded = cbor.decode(authdata)
    except (ValueError, IndexError, KeyError, struct.error) as e:
        raise AttestationError(f"authenticator data is not a CBOR byte string: {e}") from e
    if not isinstance(decoded, bytes):
        raise AttestationError("authenticator data is not a CBOR byte string")
    return cert, sig, decoded


def _cn(cert: x509.Certificate) -> str:
    attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else cert.subject.rfc4514_string()


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return bool(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        return False


def _check_validity(cert: x509.Certificate, at: datetime.datetime) -> None:
    if not cert.not_valid_before_utc <= at <= cert.not_valid_after_utc:
        raise AttestationError(f"certificate {_cn(cert)!r} not valid at {at.isoformat()}")


def verify_chain(
    leaf: x509.Certificate, store: TrustStore, at: datetime.datetime
) -> list[x509.Certificate]:
    """Return the path leaf..root, or raise. Only pinned certificates may appear above the leaf."""
    if _is_ca(leaf):
        raise AttestationError("attestation certificate is a CA certificate")
    _check_validity(leaf, at)
    path = [leaf]
    current = leaf
    for _ in range(MAX_CHAIN):
        for root in store.roots:
            if root.subject == current.issuer:
                try:
                    current.verify_directly_issued_by(root)
                except (InvalidSignature, ValueError, TypeError):
                    continue
                return [*path, root]
        for inter in store.intermediates:
            if inter.subject == current.issuer and inter not in path:
                try:
                    current.verify_directly_issued_by(inter)
                except (InvalidSignature, ValueError, TypeError):
                    continue
                if not _is_ca(inter):
                    raise AttestationError(f"intermediate {_cn(inter)!r} is not a CA")
                _check_validity(inter, at)
                path.append(inter)
                current = inter
                break
        else:
            raise AttestationError(
                f"attestation certificate does not chain to a pinned root "
                f"(stuck at issuer {current.issuer.rfc4514_string()!r})"
            )
    raise AttestationError("certificate chain too long")


def _cert_aaguid(cert: x509.Certificate) -> bytes | None:
    try:
        ext = cert.extensions.get_extension_for_oid(OID_FIDO_AAGUID).value
    except x509.ExtensionNotFound:
        return None
    raw = ext.value if isinstance(ext, x509.UnrecognizedExtension) else b""
    if len(raw) != 18 or raw[:2] != b"\x04\x10":
        raise AttestationError("malformed AAGUID extension in attestation certificate")
    return raw[2:]


def _cose_matches(cose: dict[int, object], key: SshSkKey) -> bool:
    if key.key_type == ED25519_SK:
        return cose.get(1) == 1 and cose.get(-1) == 6 and cose.get(-2) == key.public
    x, y = cose.get(-2), cose.get(-3)
    return (
        cose.get(1) == 2
        and cose.get(-1) == 1
        and isinstance(x, bytes)
        and isinstance(y, bytes)
        and b"\x04" + x + y == key.public
    )


def verify_attestation(
    pubkey: str,
    attestation: bytes,
    challenge: bytes,
    store: TrustStore | None = None,
    require_uv: bool = False,
    at: datetime.datetime | None = None,
) -> VerifiedKey:
    """Verify that `pubkey` was generated in hardware attested by `attestation`."""
    store = store or TrustStore.builtin()
    at = at or datetime.datetime.now(datetime.UTC)
    key = parse_sk_public_key(pubkey)
    cert_der, sig, authdata_raw = parse_attestation(attestation)
    try:
        leaf = x509.load_der_x509_certificate(cert_der)
    except ValueError as e:
        raise AttestationError(f"bad attestation certificate: {e}") from e
    path = verify_chain(leaf, store, at)

    signed = authdata_raw + hashlib.sha256(challenge).digest()
    leaf_pub = leaf.public_key()
    try:
        if isinstance(leaf_pub, ec.EllipticCurvePublicKey):
            leaf_pub.verify(sig, signed, ec.ECDSA(hashes.SHA256()))
        elif isinstance(leaf_pub, ed25519.Ed25519PublicKey):
            leaf_pub.verify(sig, signed)
        else:
            raise AttestationError(f"unsupported attestation key {type(leaf_pub).__name__}")
    except InvalidSignature as e:
        raise AttestationError("attestation signature invalid (wrong challenge or tampered)") from e

    try:
        ad = AuthenticatorData(authdata_raw)
    except Exception as e:
        raise AttestationError(f"bad authenticator data: {e}") from e
    if ad.rp_id_hash != hashlib.sha256(key.application.encode()).digest():
        raise AttestationError("authenticator data is for another application")
    if not ad.is_user_present():
        raise AttestationError("user presence flag not set")
    if require_uv and not ad.is_user_verified():
        raise AttestationError("user verification flag not set")
    cred = ad.credential_data
    if cred is None:
        raise AttestationError("no attested credential data")
    if not _cose_matches(dict(cred.public_key), key):
        raise AttestationError("attested credential is not this SSH public key")
    cert_aaguid = _cert_aaguid(leaf)
    if cert_aaguid is not None and cert_aaguid != bytes(cred.aaguid):
        raise AttestationError("AAGUID in certificate differs from authenticator data")

    return VerifiedKey(
        key=key,
        aaguid=str(uuid.UUID(bytes=bytes(cred.aaguid))),
        chain=[_cn(c) for c in path],
        user_verified=ad.is_user_verified(),
    )
