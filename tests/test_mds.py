"""FIDO MDS3 checks: synthetic blobs (positive, negatives) and the real blob when downloaded."""

from __future__ import annotations

import base64
import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from synth import NOW, enroll, make_mds, make_vendor

from hwssh._attest import AttestationError, TrustStore, verify_attestation
from hwssh._mds import verify_blob

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def vendor():  # type: ignore[no-untyped-def]
    return make_vendor()


def check(vendor, blob, root, **kw):  # type: ignore[no-untyped-def]
    mds = verify_blob(blob, roots=[root], at=NOW)
    e = enroll(vendor)
    return verify_attestation(e.pubkey, e.attestation, e.challenge, store=vendor.store,
                              at=NOW, mds=mds, **kw)


def test_positive(vendor) -> None:  # type: ignore[no-untyped-def]
    blob, root = make_mds(vendor)
    assert check(vendor, blob, root).model == "Test Authenticator"


def test_wrong_signer_name(vendor) -> None:  # type: ignore[no-untyped-def]
    blob, root = make_mds(vendor, signer_name="evil.example.com")
    with pytest.raises(AttestationError, match="not signed by"):
        verify_blob(blob, roots=[root], at=NOW)


def test_untrusted_root(vendor) -> None:  # type: ignore[no-untyped-def]
    blob, _ = make_mds(vendor)
    _, other = make_mds(vendor)
    with pytest.raises(AttestationError, match="pinned root"):
        verify_blob(blob, roots=[other], at=NOW)


def test_tampered_payload(vendor) -> None:  # type: ignore[no-untyped-def]
    blob, root = make_mds(vendor)
    blob2, _ = make_mds(vendor, status="REVOKED")
    h, _, s = blob.split(b".")
    forged = b".".join([h, blob2.split(b".")[1], s])
    with pytest.raises(AttestationError, match="signature invalid"):
        verify_blob(forged, roots=[root], at=NOW)


def test_stale(vendor) -> None:  # type: ignore[no-untyped-def]
    blob, root = make_mds(vendor, next_update="2026-11-01")
    with pytest.raises(AttestationError, match="stale"):
        verify_blob(blob, roots=[root], at=NOW)
    verify_blob(blob, roots=[root], at=NOW, allow_stale=True)


@pytest.mark.parametrize("status", ["REVOKED", "ATTESTATION_KEY_COMPROMISE",
                                    "USER_VERIFICATION_BYPASS"])
def test_compromised(vendor, status) -> None:  # type: ignore[no-untyped-def]
    blob, root = make_mds(vendor, status=status)
    with pytest.raises(AttestationError, match=status):
        check(vendor, blob, root)


def test_unknown_aaguid(vendor) -> None:  # type: ignore[no-untyped-def]
    blob, root = make_mds(vendor, aaguid=uuid.uuid4())
    with pytest.raises(AttestationError, match="not in FIDO metadata"):
        check(vendor, blob, root)


def test_root_not_listed_for_model(vendor) -> None:  # type: ignore[no-untyped-def]
    blob, root = make_mds(vendor, listed=make_vendor().root)
    with pytest.raises(AttestationError, match="no certificate FIDO metadata lists"):
        check(vendor, blob, root)


real = pytest.mark.skipif(not (FIX / "mds.jwt").exists(),
                          reason="no real blob; run hwssh mds-update tests/fixtures/mds.jwt")


@real
def test_real_blob_and_yubikey() -> None:
    mds = verify_blob((FIX / "mds.jwt").read_bytes())
    y = FIX / "yubikey"
    v = verify_attestation((y / "id_ed25519_sk.pub").read_text(), (y / "attest.bin").read_bytes(),
                           (y / "challenge.bin").read_bytes(), mds=mds)
    assert v.model and v.model.startswith("YubiKey 5")


@real
def test_pinned_yubico_certs_listed_in_mds() -> None:
    """Independent reference: every pinned Yubico cert is listed by the FIDO Alliance."""
    mds = verify_blob((FIX / "mds.jwt").read_bytes())
    listed = {base64.b64decode(c)
              for e in mds.payload["entries"]
              for c in e.get("metadataStatement", {}).get("attestationRootCertificates", [])}
    store = TrustStore.builtin()
    for c in store.roots + store.intermediates:
        assert c.public_bytes(serialization.Encoding.DER) in listed, c.subject.rfc4514_string()
