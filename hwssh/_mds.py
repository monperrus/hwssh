"""FIDO Alliance Metadata Service (MDS3): an independent list of authenticator models.

The blob is a JWT signed by `mds.fidoalliance.org`, chaining to GlobalSign Root CA - R3.
With it, a key is accepted only if its AAGUID is listed, the attestation path contains one
of the certificates the FIDO Alliance lists for that AAGUID, and no compromise was reported.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import json
import urllib.request
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from hwssh._attest import AttestationError, TrustStore, verify_chain

MDS_URL = "https://mds3.fidoalliance.org/"
MDS_SIGNER = "mds.fidoalliance.org"
BAD_STATUS = frozenset({
    "REVOKED",
    "ATTESTATION_KEY_COMPROMISE",
    "USER_VERIFICATION_BYPASS",
    "USER_KEY_REMOTE_COMPROMISE",
    "USER_KEY_PHYSICAL_COMPROMISE",
})


def _b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def builtin_root() -> list[x509.Certificate]:
    return x509.load_pem_x509_certificates(
        resources.files("hwssh.roots").joinpath("mds-root.pem").read_bytes()
    )


def _signer_names(cert: x509.Certificate) -> set[str]:
    names = {str(a.value) for a in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)}
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names |= set(san.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass
    return names


@dataclass(frozen=True)
class Mds:
    payload: dict[str, Any]

    @property
    def next_update(self) -> datetime.date:
        return datetime.date.fromisoformat(self.payload["nextUpdate"])

    def entry(self, aaguid: str) -> dict[str, Any] | None:
        for e in self.payload["entries"]:
            if e.get("aaguid") == aaguid:
                return dict(e)
        return None

    def check(self, aaguid: str, path_der: list[bytes]) -> str:
        """Raise unless the authenticator is listed, chains to a listed cert, and is not compromised.
        Return the model description."""
        e = self.entry(aaguid)
        if e is None:
            raise AttestationError(f"AAGUID {aaguid} not in FIDO metadata (MDS3 no. {self.payload['no']})")
        bad = [s["status"] for s in e.get("statusReports", []) if s.get("status") in BAD_STATUS]
        if bad:
            raise AttestationError(f"FIDO metadata reports {', '.join(bad)} for AAGUID {aaguid}")
        ms = e.get("metadataStatement", {})
        listed = {base64.b64decode(c) for c in ms.get("attestationRootCertificates", [])}
        if not listed & set(path_der):
            raise AttestationError("attestation path holds no certificate FIDO metadata lists for it")
        return str(ms.get("description", ""))


def verify_blob(
    jwt: bytes,
    roots: list[x509.Certificate] | None = None,
    signer: str = MDS_SIGNER,
    at: datetime.datetime | None = None,
    allow_stale: bool = False,
) -> Mds:
    """Verify the MDS3 JWT (signature, chain to pinned root, signer name, freshness)."""
    at = at or datetime.datetime.now(datetime.UTC)
    try:
        h64, p64, s64 = jwt.decode().strip().split(".")
        header = json.loads(_b64url(h64))
        sig = _b64url(s64)
        x5c = [x509.load_der_x509_certificate(base64.b64decode(c)) for c in header["x5c"]]
    except (ValueError, KeyError, binascii.Error) as e:
        raise AttestationError(f"malformed MDS blob: {e}") from e
    if not x5c:
        raise AttestationError("MDS blob has no signing certificate")
    leaf = x5c[0]
    verify_chain(leaf, TrustStore(roots or builtin_root(), x5c[1:]), at)
    if signer not in _signer_names(leaf):
        raise AttestationError(f"MDS blob not signed by {signer}")
    signed = f"{h64}.{p64}".encode()
    key = leaf.public_key()
    try:
        if header.get("alg") == "RS256" and isinstance(key, rsa.RSAPublicKey):
            key.verify(sig, signed, padding.PKCS1v15(), hashes.SHA256())
        elif header.get("alg") == "ES256" and isinstance(key, ec.EllipticCurvePublicKey):
            r, s = int.from_bytes(sig[:32]), int.from_bytes(sig[32:])
            key.verify(encode_dss_signature(r, s), signed, ec.ECDSA(hashes.SHA256()))
        else:
            raise AttestationError(f"unsupported MDS signature alg {header.get('alg')!r}")
    except InvalidSignature as e:
        raise AttestationError("MDS blob signature invalid") from e
    mds = Mds(json.loads(_b64url(p64)))
    if not allow_stale and at.date() > mds.next_update:
        raise AttestationError(
            f"MDS blob stale: nextUpdate {mds.next_update}, run `hwssh mds-update`"
        )
    return mds


def load(path: Path, **kw: Any) -> Mds:
    return verify_blob(path.read_bytes(), **kw)


def fetch(url: str = MDS_URL, timeout: float = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "hwssh"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data: bytes = r.read()
    return data
