"""hwssh: accept only SSH keys provably generated inside FIDO2 hardware."""

from __future__ import annotations

from hwssh._attest import AttestationError, VerifiedKey, verify_attestation

__all__ = ["AttestationError", "VerifiedKey", "verify_attestation"]
