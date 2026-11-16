#!/usr/bin/env bash
# End-to-end test of ssh-tpm-ca-authority with EK certificate verification
# (monperrus/ssh-tpm-ca-authority, branch ek-cert-verification) on this machine's TPM
# (/dev/tpmrm0, STMicroelectronics): the CA requires the manufacturer's EK certificate,
# issues a 5-minute SSH certificate, ssh-tpm-agent v0.9.0 presents it to sshd.
#
#   TPM_EH_AUTH=<endorsement hierarchy password, empty if none> run.sh WORKDIR
#
# e2e/main.go drives the CA and the client in-process, with a software TPM simulator as the
# impostor. No persistent TPM object or NV index is written on the real TPM.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mkdir -p "$1" && cd "$1" && pwd)
CA_REPO=${CA_REPO:-https://github.com/monperrus/ssh-tpm-ca-authority}
CA_REV=${CA_REV:-699dd7a}   # ek-cert-verification
AGENT_REV=v0.9.0            # ssh-tpm-agent
fails=0; ok(){ echo "PASS $*"; }; bad(){ echo "FAIL $*"; fails=$((fails+1)); }

[[ -d $W/ca ]] || git clone -q "$CA_REPO" "$W/ca"
git -C "$W/ca" fetch -q origin 2>/dev/null
git -C "$W/ca" checkout -q -f "$CA_REV" && git -C "$W/ca" clean -qfd
mkdir -p "$W/ca/cmd/e2e" && cp "$HERE/e2e/main.go" "$W/ca/cmd/e2e/"
[[ -d $W/agent ]] || git clone -q https://github.com/Foxboron/ssh-tpm-agent "$W/agent"
git -C "$W/agent" checkout -q $AGENT_REV
(cd "$W/ca" && TPM_EH_AUTH= go test -count=1 ./... >/dev/null) && ok "fork unit tests (simulator, fake manufacturer)" || bad "fork unit tests"
(cd "$W/ca" && go build -o "$W/bin/e2e" ./cmd/e2e) || exit 1
(cd "$W/agent" && go build -o "$W/bin/" ./cmd/ssh-tpm-agent ./cmd/ssh-tpm-add) || exit 1
docker build -q -t tpmca-sshd "$HERE" >/dev/null || exit 1

OUT=$W/out; mkdir -p "$OUT"; rm -f "$OUT"/*
SSH=(ssh -F /dev/null -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes)
SOCK=$(mktemp -u -p "${XDG_RUNTIME_DIR:-/tmp}" tpmca.XXXX.sock); export SSH_TPM_AUTH_SOCK=$SOCK
cleanup(){ docker rm -f tpmca-now tpmca-later >/dev/null 2>&1; [[ -n ${AG:-} ]] && kill "$AG" 2>/dev/null; rm -f -- "$SOCK"; }
trap cleanup EXIT

# 1. CA protocol: real TPM (P1) and impostors (N1-N6)
"$W/bin/e2e" "$OUT" "$HERE/stm-roots.pem" "$HERE/stm-intermediates.pem" "$HERE/infineon-roots.pem" || bad "CA protocol"

# 2. SSH: sshd trusting the CA, now and with the clock 6 minutes ahead
docker run -d --name tpmca-now -p 127.0.0.1:2223:22 -v "$OUT/ca.pub:/etc/ssh/ca.pub:ro" tpmca-sshd >/dev/null
docker run -d --name tpmca-later -p 127.0.0.1:2224:22 -v "$OUT/ca.pub:/etc/ssh/ca.pub:ro" tpmca-sshd \
  faketime -f +6m /usr/sbin/sshd -D -e >/dev/null
"$W/bin/ssh-tpm-agent" -l "$SOCK" >"$W/agent.log" 2>&1 & AG=$!
for _ in $(seq 50); do [[ -S $SOCK ]] && break; sleep 0.1; done
"$W/bin/ssh-tpm-add" "$OUT/id_ecdsa.tpm" >/dev/null
sleep 1
out=$("${SSH[@]}" -p 2223 -o IdentityAgent="$SOCK" alice@127.0.0.1 'echo tpm-in' 2>&1)
[[ $out == *tpm-in* ]] && ok "TPM key + CA certificate logs in" || bad "TPM login: $out"
ssh-keygen -q -t ecdsa -N '' -f "$OUT/soft" -C soft
out=$("${SSH[@]}" -p 2223 -o IdentitiesOnly=yes -o IdentityAgent=none -i "$OUT/soft" alice@127.0.0.1 'echo in' 2>&1)
[[ $out == *"Permission denied"* ]] && ok "software key without certificate refused" || bad "soft key: $out"
out=$("${SSH[@]}" -p 2224 -o IdentityAgent="$SOCK" alice@127.0.0.1 'echo tpm-in' 2>&1)
[[ $out == *"Permission denied"* ]] && docker logs tpmca-later 2>&1 | grep -q "Certificate invalid: expired" \
  && ok "same certificate 6 minutes later refused (expired)" || bad "expiry: $out"

echo "fails=$fails"; [[ $fails == 0 ]]
