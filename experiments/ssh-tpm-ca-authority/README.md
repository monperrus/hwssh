# ssh-tpm-ca-authority with EK certificate verification

[Foxboron/ssh-tpm-ca-authority](https://github.com/Foxboron/ssh-tpm-ca-authority) (Morten Linderud,
last commit e92b303, 2024-08-31, "POC quality") is an SSH certificate authority that issues
5-minute certificates for keys bound to a TPM. Upstream trusts the endorsement key (EK) name
typed into `config.yaml` and never reads the manufacturer's EK certificate, so a software TPM
gets certificates once its EK name is listed.

The fork [monperrus/ssh-tpm-ca-authority, branch `ek-cert-verification`](https://github.com/monperrus/ssh-tpm-ca-authority/tree/ek-cert-verification)
adds three commits:

- `oidc_connector: none`: issue on the TPM binding alone, without the interactive login
  (upstream's `go test` opened a browser and hung).
- EK certificate verification: the client reads the EK certificate from NV index `0x01c0000a`;
  with `ek_roots` set, the CA requires it to chain to a trusted manufacturer root and to certify
  the EK the credential challenge is encrypted to.
- `TPM_EH_AUTH`: endorsement hierarchy password (upstream hard-codes an empty one and fails with
  `TPM_RC_BAD_AUTH` on TPMs that have one, like this machine).

## Running

```sh
TPM_EH_AUTH=<endorsement password, empty if none> ./run.sh /tmp/tpmca-work
```

`run.sh` builds the fork at 699dd7a with the driver `e2e/main.go`, and `ssh-tpm-agent` v0.9.0.
The CA trusts STMicroelectronics (`stm-roots.pem`: GlobalSign Trusted Platform Module ECC Root CA;
`stm-intermediates.pem`: STM TPM ECC Root CA 01, STM TPM ECC Intermediate CA 01). These are
byte-identical to the copies in Microsoft's [TrustedTpm.cab](https://go.microsoft.com/fwlink/?linkid=2097925)
and to the ones served by GlobalSign. No persistent TPM object or NV index is written on the
real TPM.

## Results (2026-11-16, Dell Latitude 7400, STMicroelectronics ST33HTPHAHC1)

13/13 checks pass:

- The fork's unit tests pass on the simulator with a fake manufacturer: trusted certificate,
  none in NV, untrusted root, certificate for another key.
- P1: the real TPM, whose EK certificate chains to STMicroelectronics, gets a 5-minute certificate.
- N1: a TPM whose EK is not the one listed for the user is rejected.
- N2: a client that cannot decrypt the credential gets no certificate.
- N3: an SSH key whose public area was changed after certification is rejected.
- N4: a software TPM simulator whose EK name is listed is rejected: it has no EK certificate.
  Upstream issues it a certificate.
- N5: the simulator presenting the real TPM's EK certificate is rejected: the certificate is
  for another key than the challenged EK.
- N6: a CA trusting only Infineon rejects the real STMicroelectronics TPM.
- sshd admits the TPM key with its certificate, refuses a software key, and refuses the same
  certificate with the clock 6 minutes ahead (`Certificate invalid: expired`).

With the EK check disabled in the fork, N4, N5 and N6 fail: the checks detect its absence.

## Remaining limits

- Third parties cannot re-verify: the EK can only decrypt, so the binding of the attestation key
  to the EK is an interactive challenge whose transcript the CA could forge. sshd sees only the
  CA signature, and the CA keeps no evidence.
- The server listens on all interfaces (`*:8080`, plain HTTP), while the upstream README says
  `127.0.0.1:8080`.
- The documented client flow does not run: in `ssh-tpm-agent` v0.9.0, `ssh-tpm-add --ca`,
  `--host`, `--user` are parsed but never used. The driver uses the client library directly.
- TPM firmware is closed, as for security keys.
