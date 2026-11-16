"""Checks against a real YubiKey attestation (tests/fixtures/capture.sh), with built-in roots."""

from __future__ import annotations

from pathlib import Path

import pytest

from hwssh._attest import AttestationError, verify_attestation

FIX = Path(__file__).parent / "fixtures" / "yubikey"
pytestmark = pytest.mark.skipif(
    not (FIX / "attest.bin").exists(), reason="no real fixture; run tests/fixtures/capture.sh"
)


def load() -> tuple[str, bytes, bytes]:
    return (
        (FIX / "id_ed25519_sk.pub").read_text(),
        (FIX / "attest.bin").read_bytes(),
        (FIX / "challenge.bin").read_bytes(),
    )


def test_real_key_proven_hardware() -> None:
    v = verify_attestation(*load(), require_uv=True)
    assert v.chain[0].startswith("Yubico") and v.chain[-1].startswith("Yubico")
    assert v.user_verified


def test_real_key_other_challenge() -> None:
    pub, att, _ = load()
    with pytest.raises(AttestationError, match="signature"):
        verify_attestation(pub, att, b"\x00" * 32)


def test_real_attestation_does_not_vouch_for_software_key() -> None:
    _, att, chal = load()
    software = (Path(__file__).parent / "fixtures" / "software_sk.pub").read_text()
    with pytest.raises(AttestationError, match="not this SSH public key"):
        verify_attestation(software, att, chal)
