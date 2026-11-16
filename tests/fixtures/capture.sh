#!/usr/bin/env bash
# Capture a real attestation fixture from a plugged-in FIDO2 key (touch + PIN).
# Writes tests/fixtures/<name>/{challenge.bin,attest.bin,id_ed25519_sk.pub,id_ed25519_sk}.
# id_ed25519_sk is a key handle, usable only with the device; it is git-ignored.
set -euo pipefail
d="$(dirname "$0")/${1:-yubikey}"
mkdir -p "$d"
rm -f "$d"/id_ed25519_sk "$d"/id_ed25519_sk.pub "$d"/attest.bin
head -c 32 /dev/urandom > "$d/challenge.bin"
ssh-keygen -q -t ed25519-sk -O verify-required -N '' -C hwssh-fixture \
  -O challenge="$d/challenge.bin" -O write-attestation="$d/attest.bin" -f "$d/id_ed25519_sk"
