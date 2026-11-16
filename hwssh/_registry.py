"""Registry of enrolled keys: `<root>/<user>/<sha256-hex>.{pub,attest,challenge}`.

Every entry carries its own evidence, so the registry can be re-verified by anyone,
and sshd only ever sees keys that re-verify at login time.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from hwssh._attest import AttestationError, TrustStore, VerifiedKey, verify_attestation

if TYPE_CHECKING:
    from hwssh._mds import Mds

USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


@dataclass(frozen=True)
class Entry:
    user: str
    stem: Path

    def verify(
        self, store: TrustStore | None, require_uv: bool = False, mds: Mds | None = None
    ) -> VerifiedKey:
        try:
            pub = self.stem.with_suffix(".pub").read_text()
            att = self.stem.with_suffix(".attest").read_bytes()
            chal = self.stem.with_suffix(".challenge").read_bytes()
        except OSError as e:
            raise AttestationError(f"incomplete entry: {e}") from e
        v = verify_attestation(pub, att, chal, store=store, require_uv=require_uv, mds=mds)
        if hashlib.sha256(v.key.blob).hexdigest() != self.stem.name:
            raise AttestationError("entry file name does not match its key")
        return v


def check_user(user: str) -> str:
    if not USER_RE.match(user):
        raise ValueError(f"invalid user name {user!r}")
    return user


def entries(root: Path, user: str | None = None) -> Iterator[Entry]:
    users = [check_user(user)] if user else sorted(
        p.name for p in root.iterdir() if p.is_dir() and USER_RE.match(p.name)
    )
    for u in users:
        d = root / u
        if not d.is_dir():
            continue
        stems = {p.with_suffix("") for p in d.iterdir() if p.suffix in (".pub", ".attest")}
        for stem in sorted(stems):
            yield Entry(u, stem)


def enroll(
    root: Path,
    user: str,
    pubkey: str,
    attestation: bytes,
    challenge: bytes,
    store: TrustStore | None = None,
    require_uv: bool = False,
    mds: Mds | None = None,
) -> tuple[VerifiedKey, Path]:
    v = verify_attestation(
        pubkey, attestation, challenge, store=store, require_uv=require_uv, mds=mds
    )
    d = root / check_user(user)
    d.mkdir(parents=True, exist_ok=True)
    stem = d / hashlib.sha256(v.key.blob).hexdigest()
    stem.with_suffix(".attest").write_bytes(attestation)
    stem.with_suffix(".challenge").write_bytes(challenge)
    stem.with_suffix(".pub").write_text(v.key.openssh() + "\n")
    return v, stem
