"""Command line: `hwssh challenge|verify|enroll|verify-registry|authorized-keys`.

Silent on success; errors on stderr with exit 1; `--json` for machine output.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from cryptography import x509

from hwssh import _mds, _registry
from hwssh._attest import AttestationError, TrustStore, VerifiedKey, verify_attestation

EPILOG = """\
enrollment, on the client:
  hwssh challenge chal.bin          # or a challenge issued by the server admin
  ssh-keygen -t ed25519-sk -O verify-required \\
      -O challenge=chal.bin -O write-attestation=attest.bin -f ~/.ssh/id_ed25519_sk
then on the server (mds-update daily, e.g. from cron):
  hwssh mds-update /var/lib/hwssh/mds.jwt
  hwssh enroll --mds /var/lib/hwssh/mds.jwt /etc/hwssh/registry alice ~/.ssh/id_ed25519_sk.pub attest.bin chal.bin
sshd_config:
  AuthorizedKeysFile none
  AuthorizedKeysCommand /usr/local/bin/hwssh authorized-keys --mds /var/lib/hwssh/mds.jwt /etc/hwssh/registry %u
  AuthorizedKeysCommandUser nobody
exit codes: 0 ok, 1 not proven hardware / failed check, 2 usage error
"""


def _store(args: argparse.Namespace) -> TrustStore | None:
    if not args.roots:
        return None
    roots: list[x509.Certificate] = []
    for p in args.roots:
        roots += x509.load_pem_x509_certificates(Path(p).read_bytes())
    return TrustStore(roots)


def _mds_of(args: argparse.Namespace) -> _mds.Mds | None:
    return _mds.load(Path(args.mds)) if args.mds else None


def _record(v: VerifiedKey, **extra: Any) -> dict[str, Any]:
    d = {
        "fingerprint": v.key.fingerprint,
        "key_type": v.key.key_type,
        "application": v.key.application,
        "aaguid": v.aaguid,
        "chain": v.chain,
        "user_verified": v.user_verified,
        "model": v.model,
    }
    d.update(extra)
    return d


def cmd_challenge(args: argparse.Namespace) -> int:
    Path(args.out).write_bytes(os.urandom(32))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    v = verify_attestation(
        Path(args.pub).read_text(),
        Path(args.attest).read_bytes(),
        Path(args.challenge).read_bytes(),
        store=_store(args),
        require_uv=args.require_uv,
        mds=_mds_of(args),
    )
    if args.json:
        print(json.dumps(_record(v)))
    return 0


def cmd_enroll(args: argparse.Namespace) -> int:
    v, stem = _registry.enroll(
        Path(args.registry),
        args.user,
        Path(args.pub).read_text(),
        Path(args.attest).read_bytes(),
        Path(args.challenge).read_bytes(),
        store=_store(args),
        require_uv=args.require_uv,
        mds=_mds_of(args),
    )
    if args.json:
        print(json.dumps(_record(v, user=args.user, entry=str(stem))))
    return 0


def cmd_verify_registry(args: argparse.Namespace) -> int:
    store = _store(args)
    mds = _mds_of(args)
    results = []
    for e in _registry.entries(Path(args.registry)):
        try:
            v = e.verify(store, require_uv=args.require_uv, mds=mds)
            results.append(_record(v, user=e.user, entry=str(e.stem), ok=True))
        except AttestationError as err:
            results.append({"user": e.user, "entry": str(e.stem), "ok": False, "error": str(err)})
    bad = [r for r in results if not r["ok"]]
    if args.json:
        print(json.dumps(results))
    else:
        for r in bad:
            print(f"{r['entry']}: {r['error']}", file=sys.stderr)
    return 1 if bad else 0


def cmd_authorized_keys(args: argparse.Namespace) -> int:
    store = _store(args)
    mds = _mds_of(args)
    for e in _registry.entries(Path(args.registry), args.user):
        try:
            v = e.verify(store, require_uv=args.require_uv, mds=mds)
        except AttestationError as err:
            print(f"hwssh: rejecting {e.stem}: {err}", file=sys.stderr)
            continue
        print(f"verify-required {v.key.openssh()} hwssh:{e.stem.name[:16]}")
    return 0


def cmd_mds_update(args: argparse.Namespace) -> int:
    blob = _mds.fetch(args.url)
    m = _mds.verify_blob(blob)  # never store an unverified blob
    out = Path(args.out)
    tmp = out.with_name(out.name + ".tmp")
    tmp.write_bytes(blob)
    tmp.chmod(0o644)
    tmp.replace(out)
    if args.json:
        print(json.dumps({"no": m.payload["no"], "nextUpdate": m.payload["nextUpdate"],
                          "entries": len(m.payload["entries"]), "path": str(out)}))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hwssh",
        description="Accept only SSH keys provably generated inside FIDO2 hardware.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="machine-readable output")
    common.add_argument(
        "--roots", action="append", metavar="PEM",
        help="trust these roots instead of the built-in vendor roots (repeatable)",
    )
    common.add_argument(
        "--require-uv", action="store_true",
        help="also require the user-verification (PIN/biometric) flag at enrollment",
    )
    common.add_argument(
        "--mds", metavar="JWT",
        help="also require the model to be listed, uncompromised, in this FIDO MDS3 blob",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("mds-update", help="download and verify the FIDO MDS3 blob, store it")
    c.add_argument("out")
    c.add_argument("--url", default=_mds.MDS_URL)
    c.add_argument("--json", action="store_true", help="machine-readable output")
    c.set_defaults(func=cmd_mds_update)

    c = sub.add_parser("challenge", help="write a fresh 32-byte challenge file")
    c.add_argument("out")
    c.set_defaults(func=cmd_challenge)

    for name, func, hlp in [
        ("verify", cmd_verify, "check one attestation; silent if it proves hardware"),
        ("enroll", cmd_enroll, "verify, then add the key to the registry"),
    ]:
        c = sub.add_parser(name, parents=[common], help=hlp)
        if name == "enroll":
            c.add_argument("registry")
            c.add_argument("user")
        c.add_argument("pub", help="the .pub file written by ssh-keygen -t *-sk")
        c.add_argument("attest", help="file from ssh-keygen -O write-attestation")
        c.add_argument("challenge", help="file given to ssh-keygen -O challenge")
        c.set_defaults(func=func)

    c = sub.add_parser("verify-registry", parents=[common],
                       help="re-verify every entry (third-party audit); silent if all hold")
    c.add_argument("registry")
    c.set_defaults(func=cmd_verify_registry)

    c = sub.add_parser("authorized-keys", parents=[common],
                       help="print verified keys of USER, for sshd AuthorizedKeysCommand")
    c.add_argument("registry")
    c.add_argument("user")
    c.set_defaults(func=cmd_authorized_keys)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rc: int = args.func(args)
        return rc
    except AttestationError as e:
        if getattr(args, "json", False):
            print(json.dumps({"ok": False, "error": str(e)}))
        print(f"hwssh: not proven hardware: {e}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as e:
        print(f"hwssh: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

