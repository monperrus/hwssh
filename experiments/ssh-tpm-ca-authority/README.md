# Evaluation of ssh-tpm-ca-authority

[Foxboron/ssh-tpm-ca-authority](https://github.com/Foxboron/ssh-tpm-ca-authority) (Morten Linderud,
last commit e92b303, 2024-08-31, "POC quality") is an SSH certificate authority that issues
5-minute certificates for keys bound to a TPM. This directory tests it end to end on a real TPM
(STMicroelectronics, `/dev/tpmrm0`) with `ssh-tpm-agent` v0.9.0 and OpenSSH sshd.

```sh
TPM_EH_AUTH=<endorsement password, empty if none> ./run.sh /tmp/tpmca-work
```

Result on 2026-11-16: 9/9 checks pass. No persistent TPM handle or NV index is written.

## Protocol

1. The client creates an attestation key (AK, restricted, `fixedTPM`) under the endorsement
   hierarchy and an ECC P-256 SSH key under the storage root key. The AK certifies the creation
   of both (`TPM2_CertifyCreation`).
2. The server checks both creation attestations and the key attributes `fixedTPM`,
   `fixedParent`, `sensitiveDataOrigin`, and that the client's endorsement key (EK) name is the
   one listed for this user in `config.yaml`.
3. The server encrypts a secret to the EK, bound to the AK name (`MakeCredential`). Only the TPM
   holding both can decrypt it (`ActivateCredential`). This proves that the SSH key lives in the
   TPM whose EK is listed.
4. The user logs in through sigstore's OIDC provider (GitHub or Google); the email must match.
5. The CA, whose key is also in a TPM, signs a user certificate valid for 5 minutes. sshd only
   trusts the CA (`TrustedUserCAKeys`).

## Checks

- P1: a TPM-bound key with a listed EK gets a certificate, valid exactly 300 s.
- N1: a TPM whose EK is not the one listed for the user gets no certificate.
- N2: a client that cannot decrypt the credential gets no certificate.
- N3: a key whose public area was changed after certification is rejected.
- sshd admits the TPM key with its certificate, refuses a software key, and refuses the same
  certificate with the clock 6 minutes ahead (`Certificate invalid: expired`).
- A software TPM simulator with a fixed seed (upstream's own test) gets a certificate once its
  EK name is listed.

## Findings

- Trust anchor: the EK name typed into `config.yaml`, collected from the client
  (`cmd/getek`). The EK certificate from the TPM manufacturer is never read (the code is a
  commented-out `TODO`), so a software TPM is issued certificates if its EK name is listed. The
  hardware guarantee is as strong as the administrator's EK enrollment procedure.
- The documented client flow does not run: `ssh-tpm-add --ca` needs "unreleased changes", and
  in `ssh-tpm-agent` v0.9.0 the `--ca`, `--host`, `--user` flags are parsed but never used. This
  test drives the client library directly (`cmd/e2e` in the patch).
- The endorsement hierarchy password is hard-coded empty: on this machine, which has one, every
  run fails with `TPM_RC_BAD_AUTH` until patched (`TPM_EH_AUTH`).
- OIDC is interactive (a browser opens), so certificates cannot be obtained unattended; upstream's
  own `go test` hangs on it. The patch skips OIDC when no connector is configured.
- The server listens on all interfaces (`*:8080`, plain HTTP), while the README says
  `127.0.0.1:8080`.
- The server keeps no evidence: sshd sees a CA signature, and a third party cannot re-verify that
  a given key was TPM-bound.
