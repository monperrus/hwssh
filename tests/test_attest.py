"""Pass/fail checks for attestation verification: one positive, many negatives, boundaries."""

from __future__ import annotations

import base64
import struct

import pytest
from synth import AAGUID, NOW, enroll, make_vendor, s

from hwssh._attest import AttestationError, verify_attestation


@pytest.fixture(scope="module")
def vendor():  # type: ignore[no-untyped-def]
    return make_vendor()


def check(e, store, **kw):  # type: ignore[no-untyped-def]
    return verify_attestation(e.pubkey, e.attestation, e.challenge, store=store, at=NOW, **kw)


def test_positive(vendor) -> None:  # type: ignore[no-untyped-def]
    v = check(enroll(vendor), vendor.store, require_uv=True)
    assert v.aaguid == str(AAGUID)
    assert v.chain == ["Test Attestation", "Test Root"]
    assert v.user_verified
    assert v.key.fingerprint.startswith("SHA256:")


def test_untrusted_root(vendor) -> None:  # type: ignore[no-untyped-def]
    impostor = make_vendor(name="Test Root")  # same name, other key
    with pytest.raises(AttestationError, match="pinned root"):
        check(enroll(impostor), vendor.store)


def test_builtin_store_rejects_synthetic(vendor) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(AttestationError, match="pinned root"):
        verify_attestation(enroll(vendor).pubkey, enroll(vendor).attestation, b"c" * 32, at=NOW)


def test_wrong_challenge(vendor) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(AttestationError, match="signature"):
        check(enroll(vendor, signed_challenge=b"x" * 32), vendor.store)


def test_challenge_replaced(vendor) -> None:  # type: ignore[no-untyped-def]
    e = enroll(vendor)
    e.challenge = b"\x00" * 32
    with pytest.raises(AttestationError, match="signature"):
        check(e, vendor.store)


def test_pubkey_substituted(vendor) -> None:  # type: ignore[no-untyped-def]
    e = enroll(vendor, attested_pub=b"\x01" * 32)
    with pytest.raises(AttestationError, match="not this SSH public key"):
        check(e, vendor.store)


def test_pubkey_swapped_between_enrollments(vendor) -> None:  # type: ignore[no-untyped-def]
    a, b = enroll(vendor), enroll(vendor)
    a.pubkey = b.pubkey
    with pytest.raises(AttestationError, match="not this SSH public key"):
        check(a, vendor.store)


def test_other_application(vendor) -> None:  # type: ignore[no-untyped-def]
    e = enroll(vendor)
    keyblob = base64.b64decode(e.pubkey.split()[1])
    # rewrite the application in the SSH key to "ssh:other"
    head = keyblob[: -len(s(b"ssh:"))]
    e.pubkey = f"{e.pubkey.split()[0]} {base64.b64encode(head + s(b'ssh:other')).decode()}"
    with pytest.raises(AttestationError, match="another application"):
        check(e, vendor.store)


def test_no_user_presence(vendor) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(AttestationError, match="presence"):
        check(enroll(vendor, flags=0x44), vendor.store)


def test_uv_boundary(vendor) -> None:  # type: ignore[no-untyped-def]
    e = enroll(vendor, flags=0x41)  # UP | AT, no UV
    assert not check(e, vendor.store).user_verified
    with pytest.raises(AttestationError, match="verification"):
        check(e, vendor.store, require_uv=True)


def test_aaguid_mismatch(vendor) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(AttestationError, match="AAGUID"):
        check(enroll(vendor, authdata_aaguid=b"\x00" * 16), vendor.store)


def test_tampered_signature(vendor) -> None:  # type: ignore[no-untyped-def]
    e = enroll(vendor)
    blob = bytearray(e.attestation)
    blob[-60] ^= 1  # inside authData
    e.attestation = bytes(blob)
    with pytest.raises(AttestationError):
        check(e, vendor.store)


def test_no_certificate(vendor) -> None:  # type: ignore[no-untyped-def]
    e = enroll(vendor)
    e.attestation = s(b"ssh-sk-attest-v01") + s(b"") + s(b"") + s(b"") + struct.pack(">I", 0)
    with pytest.raises(AttestationError, match="no attestation certificate"):
        check(e, vendor.store)


def test_plain_ed25519_rejected(vendor) -> None:  # type: ignore[no-untyped-def]
    e = enroll(vendor)
    e.pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG test"
    with pytest.raises(AttestationError, match="not a FIDO"):
        check(e, vendor.store)


def test_expired_at_check_time(vendor) -> None:  # type: ignore[no-untyped-def]
    e = enroll(vendor)
    with pytest.raises(AttestationError, match="not valid"):
        verify_attestation(
            e.pubkey, e.attestation, e.challenge, store=vendor.store,
            at=NOW.replace(year=2040),
        )
