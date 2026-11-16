"""CLI and registry checks against a synthetic vendor root."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from synth import enroll, make_vendor

from hwssh.cli import main


@pytest.fixture
def env(tmp_path: Path):  # type: ignore[no-untyped-def]
    v = make_vendor()
    roots = tmp_path / "roots.pem"
    roots.write_bytes(v.root.public_bytes(serialization.Encoding.PEM))
    e = enroll(v)
    (tmp_path / "k.pub").write_text(e.pubkey)
    (tmp_path / "a.bin").write_bytes(e.attestation)
    (tmp_path / "c.bin").write_bytes(e.challenge)
    return tmp_path, roots, v


def files(d: Path) -> list[str]:
    return [str(d / "k.pub"), str(d / "a.bin"), str(d / "c.bin")]


def test_verify_silent_on_success(env, capsys) -> None:  # type: ignore[no-untyped-def]
    d, roots, _ = env
    assert main(["verify", "--roots", str(roots), *files(d)]) == 0
    assert capsys.readouterr() == ("", "")


def test_verify_builtin_roots_reject_synthetic(env, capsys) -> None:  # type: ignore[no-untyped-def]
    d, _, _ = env
    assert main(["verify", *files(d)]) == 1
    assert "not proven hardware" in capsys.readouterr().err


def test_challenge(tmp_path: Path) -> None:
    out = tmp_path / "c"
    assert main(["challenge", str(out)]) == 0
    assert len(out.read_bytes()) == 32


def test_enroll_then_authorized_keys(env, capsys) -> None:  # type: ignore[no-untyped-def]
    d, roots, _ = env
    reg = d / "reg"
    assert main(["enroll", "--roots", str(roots), str(reg), "alice", *files(d)]) == 0
    assert main(["verify-registry", "--roots", str(roots), str(reg)]) == 0
    assert capsys.readouterr() == ("", "")
    assert main(["authorized-keys", "--roots", str(roots), str(reg), "alice"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 1 and out[0].startswith("verify-required sk-ssh-ed25519@openssh.com ")
    assert main(["authorized-keys", "--roots", str(roots), str(reg), "bob"]) == 0
    assert capsys.readouterr().out == ""


def test_registry_tamper_detected(env, capsys) -> None:  # type: ignore[no-untyped-def]
    d, roots, v = env
    reg = d / "reg"
    main(["enroll", "--roots", str(roots), str(reg), "alice", *files(d)])
    # Attacker drops a software key with a forged entry: swap the .pub for another key.
    other = enroll(v)
    entry = next((reg / "alice").glob("*.pub"))
    entry.write_text(other.pubkey)
    capsys.readouterr()
    assert main(["verify-registry", "--roots", str(roots), str(reg), "--json"]) == 1
    res = json.loads(capsys.readouterr().out)
    assert res[0]["ok"] is False
    assert main(["authorized-keys", "--roots", str(roots), str(reg), "alice"]) == 0
    cap = capsys.readouterr()
    assert cap.out == "" and "rejecting" in cap.err


def test_registry_plain_key_dropped_in(env, capsys) -> None:  # type: ignore[no-untyped-def]
    d, roots, _ = env
    reg = d / "reg" / "alice"
    reg.mkdir(parents=True)
    (reg / ("0" * 64 + ".pub")).write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG x\n")
    assert main(["authorized-keys", "--roots", str(roots), str(d / "reg"), "alice"]) == 0
    assert capsys.readouterr().out == ""


def test_enroll_rejects_bad_user(env, capsys) -> None:  # type: ignore[no-untyped-def]
    d, roots, _ = env
    assert main(["enroll", "--roots", str(roots), str(d / "reg"), "../etc", *files(d)]) == 1
    assert not (d / "etc").exists()
