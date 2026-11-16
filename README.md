# hwssh — provably hardware SSH keys

An SSH server configured with hwssh admits only keys whose private key was **generated inside
a FIDO2 authenticator**, proven by a verified attestation chain to a pinned vendor root.
Every admitted key is stored with its attestation, so anyone can re-verify the claim offline.

Background: [Provable hardware wallets](https://www.monperrus.net/martin/provable-hardware-wallets).

## Why the key type is not enough

`sk-ssh-ed25519@openssh.com` keys *usually* live on a security key, but OpenSSH loads any
middleware via `SSH_SK_PROVIDER`, so software can produce such keys. OpenSSH never checks the
attestation it can write at enrollment. hwssh does, and sshd only sees keys that pass.

## Usage

Client (enrollment, touch + PIN):

```sh
hwssh challenge chal.bin
ssh-keygen -t ed25519-sk -O verify-required \
    -O challenge=chal.bin -O write-attestation=attest.bin -f ~/.ssh/id_ed25519_sk
```

Server:

```sh
hwssh enroll /etc/hwssh/registry alice id_ed25519_sk.pub attest.bin chal.bin
hwssh verify-registry /etc/hwssh/registry          # audit: silent when every entry holds
hwssh verify id_ed25519_sk.pub attest.bin chal.bin --json   # one-off check
```

sshd: use [`config/sshd_config`](config/sshd_config). Keys come only from
`AuthorizedKeysCommand hwssh authorized-keys`, which re-verifies each entry at every login;
`AuthorizedKeysFile none`, passwords, keyboard-interactive and non-`sk` algorithms are off,
and `PubkeyAuthOptions verify-required` demands PIN/biometric on every login.

All commands are silent on success, write errors to stderr, exit 1 when hardware is not
proven, and take `--json`.

## What is verified

1. The attestation certificate chains to a pinned root
   ([`hwssh/roots/`](hwssh/roots), Yubico for now; SHA-256 fingerprints inside).
2. Its signature covers `authData || SHA256(challenge)`.
3. The credential public key in `authData` is the SSH public key, for the same application.
4. User presence is set (user verification too with `--require-uv`).
5. The certificate's AAGUID, when present, equals the one in `authData`.

## What is not proven

- That the authenticator firmware does what the vendor says: it is closed, so the
  attestation is a vendor statement about a device model, not an audit of its code.
- Independence from the vendor: a leaked or misused vendor attestation key breaks the proof.
- Identity of the device: FIDO batch attestation shares one certificate across many devices.
- Freshness: the challenge binds the attestation to the enrollment, but hwssh does not
  track which challenges it issued.

## Development

```sh
uv sync
uv run pytest                     # synthetic CA positives/negatives (+ real key if captured)
tests/fixtures/capture.sh         # capture a real YubiKey attestation (touch + PIN)
tests/e2e/run.sh                  # docker sshd: password, plain key, forged entry refused
tests/e2e/run.sh --hardware       # ... and the YubiKey logs in (touch + PIN)
```

License: MIT.
