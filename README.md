# hwssh — provably hardware SSH keys

An SSH server configured with hwssh admits only keys whose private key was generated inside
a FIDO2 authenticator, proven by a verified attestation chain to a pinned vendor root.
Every admitted key is stored with its attestation, so anyone can re-verify the claim offline.

See <https://www.monperrus.net/martin/provably-hardware-ssh-protection>

## Usage

Client (enrollment, one touch):

```sh
hwssh challenge chal.bin
ssh-keygen -t ed25519-sk -O no-touch-required \
    -O challenge=chal.bin -O write-attestation=attest.bin -f ~/.ssh/id_ed25519_sk
```

Server:

```sh
hwssh mds-update /var/lib/hwssh/mds.jwt            # FIDO metadata; run daily (cron)
hwssh enroll --mds /var/lib/hwssh/mds.jwt /etc/hwssh/registry alice id_ed25519_sk.pub attest.bin chal.bin
hwssh verify-registry --mds /var/lib/hwssh/mds.jwt /etc/hwssh/registry   # audit: silent when all hold
hwssh verify id_ed25519_sk.pub attest.bin chal.bin --json                # one-off check
```

sshd: use [`config/sshd_config`](config/sshd_config). Keys come only from
`AuthorizedKeysCommand hwssh authorized-keys`, which re-verifies each entry at every login;
without a fresh FIDO metadata blob no key is served (fail closed);
`AuthorizedKeysFile none`, passwords, keyboard-interactive and non-`sk` algorithms are off,
No touch or PIN is demanded at login (`PubkeyAuthOptions none`, keys served with
`no-touch-required`), so the key works unattended; `authorized-keys --options verify-required`
demands a PIN instead.

All commands are silent on success, write errors to stderr, exit 1 when hardware is not
proven, and take `--json`.

## What is verified

1. The attestation certificate chains to a pinned root
   ([`hwssh/roots/`](hwssh/roots), Yubico for now; SHA-256 fingerprints inside).
2. Its signature covers `authData || SHA256(challenge)`.
3. The credential public key in `authData` is the SSH public key, for the same application.
4. User presence is set (user verification too with `--require-uv`).
5. The certificate's AAGUID, when present, equals the one in `authData`.
6. With `--mds`: the [FIDO Alliance Metadata Service](https://fidoalliance.org/metadata/) blob
   is signed by `mds.fidoalliance.org` (chain to pinned GlobalSign Root CA - R3) and not past its
   `nextUpdate`; it lists the AAGUID, lists a certificate of the attestation path for that
   AAGUID, and reports no compromise (`REVOKED`, `ATTESTATION_KEY_COMPROMISE`,
   `USER_VERIFICATION_BYPASS`, `USER_KEY_*_COMPROMISE`). This is an independent check of the
   pinned vendor roots: `tests/test_mds.py` asserts every pinned Yubico certificate is listed.

## What is not proven

- That the authenticator firmware does what the vendor says: it is closed, so the
  attestation is a vendor statement about a device model, not an audit of its code.
- Independence from the vendor: a leaked or misused vendor attestation key breaks the proof.
- Identity of the device: FIDO batch attestation shares one certificate across many devices.
- Revocation of individual certificates: CRLs of the vendor and MDS chains are not fetched.
- Freshness: the challenge binds the attestation to the enrollment, but hwssh does not
  track which challenges it issued.

## Development

```sh
uv sync
uv run hwssh mds-update tests/fixtures/mds.jwt   # real FIDO metadata for tests (git-ignored)
uv run pytest                     # synthetic CA positives/negatives, real key and real MDS
tests/fixtures/capture.sh         # capture a real YubiKey attestation (one touch)
tests/e2e/run.sh                  # docker sshd: password, plain key, forged entry refused;
                                  # YubiKey logs in unattended if plugged in
tests/e2e/run.sh --hardware       # same, a missing YubiKey is a failure
```

License: MIT.
