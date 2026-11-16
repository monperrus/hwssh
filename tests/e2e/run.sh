#!/usr/bin/env bash
# End-to-end: hardened sshd in docker admits only attested FIDO keys.
#   tests/e2e/run.sh            all checks; logs in with the YubiKey fixture if one is plugged in
#   tests/e2e/run.sh --hardware same, and a missing YubiKey is a failure
# Unattended: the fixture key needs no touch and no PIN at login.
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

# Build context: registry with the real fixture (verified with built-in Yubico roots and FIDO MDS)
# plus a forged entry; a plain key in alice's ~/.ssh/authorized_keys.
rm -rf $E2E/registry && mkdir -p $E2E/registry/alice
ssh-keygen -q -t ed25519 -N '' -f "$tmp/plain" -C plain
cp "$tmp/plain.pub" $E2E/plain_authorized_keys
forged=$E2E/registry/alice/$(printf '%064d' 0)
cp "$tmp/plain.pub" "$forged.pub"; printf x > "$forged.attest"; printf x > "$forged.challenge"
if [[ ! -f tests/fixtures/mds.jwt ]]; then
  uv run -q hwssh mds-update tests/fixtures/mds.jwt || { echo "FAIL: no FIDO MDS blob"; exit 1; }
fi
enrolled=0
if [[ -f $FIX/attest.bin ]]; then
  if uv run -q hwssh enroll --mds tests/fixtures/mds.jwt $E2E/registry alice $FIX/id_ed25519_sk.pub $FIX/attest.bin $FIX/challenge.bin; then
    enrolled=1; ok
  else bad "real YubiKey fixture does not enroll with built-in roots and MDS"; fi
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
            "authenticationmethods publickey" "pubkeyauthoptions none" \
            "pubkeyacceptedalgorithms sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com"; do
  grep -qx "$want" <<<"$cfg" && ok || bad "sshd -T lacks '$want'"
done

# 2. registry as sshd sees it: only the attested key, the forged entry is rejected
ak=$(grep '^AuthorizedKeysCommand ' config/sshd_config | sed 's/^AuthorizedKeysCommand //; s/%u/alice/')
keys=$(docker exec -u nobody $NAME $ak 2>"$tmp/ak.err")
[[ $(grep -c . <<<"$keys") -eq $enrolled ]] && ok || bad "authorized-keys printed: $keys"
grep -q "rejecting .*$(printf '%064d' 0)" "$tmp/ak.err" && ok || bad "forged registry entry not rejected"
if [[ $enrolled == 1 ]]; then
  grep -qF "$(cut -d' ' -f2 $FIX/id_ed25519_sk.pub)" <<<"$keys" && ok || bad "fixture key not served"
fi
# fail closed: without the FIDO metadata blob, no key is served
none=$(docker exec -u nobody $NAME ${ak/\/var\/lib\/hwssh\/mds.jwt//nonexistent} 2>/dev/null)
[[ -z $none ]] && ok || bad "keys served without MDS blob: $none"
docker exec $NAME hwssh verify-registry /etc/hwssh/registry >/dev/null 2>&1 \
  && bad "verify-registry accepted a forged entry" || ok

# 3. plain ed25519 key present in ~/.ssh/authorized_keys: refused
out=$("${SSH[@]}" -o BatchMode=yes -o IdentitiesOnly=yes -i "$tmp/plain" alice@127.0.0.1 echo in 2>&1)
[[ $out == *"Permission denied (publickey)"* ]] && ok || bad "plain key: $out"

# 4. correct password: refused, and sshd offers nothing but publickey
out=$(SSHPASS=hunter2 sshpass -e "${SSH[@]}" -o PreferredAuthentications=password,keyboard-interactive \
      -o PubkeyAuthentication=no alice@127.0.0.1 echo in 2>&1)
[[ $out == *"Permission denied (publickey)"* ]] && ok || bad "password: $out"

# 5. hardware login, unattended, when the YubiKey is plugged in
if [[ $enrolled == 1 && -f $FIX/id_ed25519_sk ]] && fido2-token -L 2>/dev/null | grep -q .; then
  out=$("${SSH[@]}" -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none \
        -i $FIX/id_ed25519_sk alice@127.0.0.1 echo hwssh-in 2>&1 </dev/null)
  [[ $out == *hwssh-in* ]] && ok || bad "YubiKey login: $out"
elif [[ $HW == --hardware ]]; then
  bad "--hardware needs the fixture, its key handle and a plugged-in YubiKey"
else
  echo "note: no YubiKey plugged in, hardware login skipped"
fi

echo "e2e: $((n-fail))/$n passed"
[[ $fail == 0 ]]
