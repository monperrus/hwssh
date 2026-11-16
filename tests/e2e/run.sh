#!/usr/bin/env bash
# End-to-end: hardened sshd in docker admits only attested FIDO keys.
#   tests/e2e/run.sh            automated checks (no touch needed)
#   tests/e2e/run.sh --hardware also log in with the YubiKey fixture (touch + PIN)
# Prints failures and one summary line; exit 1 if any check fails.
set -uo pipefail
cd "$(dirname "$0")/../.."
E2E=tests/e2e
FIX=tests/fixtures/yubikey
PORT=${HWSSH_E2E_PORT:-2222}
NAME=hwssh-e2e
HW=${1:-}
fail=0; n=0
ok()   { n=$((n+1)); }
bad()  { n=$((n+1)); fail=$((fail+1)); echo "FAIL: $*"; }

tmp=$(mktemp -d); trap 'rm -rf "$tmp"; docker rm -f $NAME >/dev/null 2>&1' EXIT
SSH=(ssh -F /dev/null -p "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
     -o LogLevel=ERROR -o ConnectTimeout=5)

# Build context: registry with the real fixture (verified with built-in Yubico roots)
# plus a forged entry; a plain key in alice's ~/.ssh/authorized_keys.
rm -rf $E2E/registry && mkdir -p $E2E/registry/alice
ssh-keygen -q -t ed25519 -N '' -f "$tmp/plain" -C plain
cp "$tmp/plain.pub" $E2E/plain_authorized_keys
forged=$E2E/registry/alice/$(printf '%064d' 0)
cp "$tmp/plain.pub" "$forged.pub"; printf x > "$forged.attest"; printf x > "$forged.challenge"
enrolled=0
if [[ -f $FIX/attest.bin ]]; then
  if uv run -q hwssh enroll $E2E/registry alice $FIX/id_ed25519_sk.pub $FIX/attest.bin $FIX/challenge.bin; then
    enrolled=1; ok
  else bad "real YubiKey fixture does not enroll with built-in roots"; fi
else
  echo "note: no $FIX/attest.bin, hardware positive skipped"
fi

docker build -q -t $NAME -f $E2E/Dockerfile . >/dev/null || { echo "FAIL: docker build"; exit 1; }
docker rm -f $NAME >/dev/null 2>&1
docker run -d --name $NAME -p "127.0.0.1:$PORT:22" $NAME >/dev/null || { echo "FAIL: docker run"; exit 1; }
for _ in $(seq 50); do "${SSH[@]}" -o BatchMode=yes nobody@127.0.0.1 true 2>&1 | grep -q 'Permission denied' && break; sleep 0.2; done

# 1. sshd effective config
cfg=$(docker exec $NAME sshd -T)
for want in "passwordauthentication no" "kbdinteractiveauthentication no" "authorizedkeysfile none" \
            "authenticationmethods publickey" "pubkeyauthoptions verify-required" \
            "pubkeyacceptedalgorithms sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com"; do
  grep -qx "$want" <<<"$cfg" && ok || bad "sshd -T lacks '$want'"
done

# 2. registry as sshd sees it: only the attested key, the forged entry is rejected
keys=$(docker exec -u nobody $NAME /usr/local/bin/hwssh authorized-keys /etc/hwssh/registry alice 2>"$tmp/ak.err")
[[ $(grep -c . <<<"$keys") -eq $enrolled ]] && ok || bad "authorized-keys printed: $keys"
grep -q "rejecting .*$(printf '%064d' 0)" "$tmp/ak.err" && ok || bad "forged registry entry not rejected"
if [[ $enrolled == 1 ]]; then
  grep -qF "$(cut -d' ' -f2 $FIX/id_ed25519_sk.pub)" <<<"$keys" && ok || bad "fixture key not served"
fi
docker exec $NAME hwssh verify-registry /etc/hwssh/registry >/dev/null 2>&1 \
  && bad "verify-registry accepted a forged entry" || ok

# 3. plain ed25519 key present in ~/.ssh/authorized_keys: refused
out=$("${SSH[@]}" -o BatchMode=yes -o IdentitiesOnly=yes -i "$tmp/plain" alice@127.0.0.1 echo in 2>&1)
[[ $out == *"Permission denied (publickey)"* ]] && ok || bad "plain key: $out"

# 4. correct password: refused, and sshd offers nothing but publickey
out=$(SSHPASS=hunter2 sshpass -e "${SSH[@]}" -o PreferredAuthentications=password,keyboard-interactive \
      -o PubkeyAuthentication=no alice@127.0.0.1 echo in 2>&1)
[[ $out == *"Permission denied (publickey)"* ]] && ok || bad "password: $out"

# 5. hardware login (touch + PIN), only with --hardware
if [[ $HW == --hardware ]]; then
  if [[ $enrolled == 1 ]]; then
    echo "touch the YubiKey and enter its PIN when asked"
    out=$("${SSH[@]}" -o IdentitiesOnly=yes -o IdentityAgent=none -i $FIX/id_ed25519_sk alice@127.0.0.1 echo hwssh-in 2>&1 </dev/tty)
    [[ $out == *hwssh-in* ]] && ok || bad "YubiKey login: $out"
  else bad "--hardware needs the fixture"; fi
fi

echo "e2e: $((n-fail))/$n passed"
[[ $fail == 0 ]]
