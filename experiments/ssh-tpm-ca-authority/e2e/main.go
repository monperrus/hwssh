// E2E driver (hwssh evaluation) for ssh-tpm-ca-authority with EK certificate verification:
// CA and client on the real TPM (/dev/tpmrm0), plus a software TPM simulator as the impostor.
//
// Usage: e2e OUTDIR ROOTS.pem INTERMEDIATES.pem OTHER-ROOTS.pem
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/foxboron/ssh-tpm-ca-authority/attest"
	"github.com/foxboron/ssh-tpm-ca-authority/client"
	"github.com/foxboron/ssh-tpm-ca-authority/server"
	ssim "github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"golang.org/x/crypto/ssh"
)

var fails int

func check(name string, ok bool, detail string) {
	if ok {
		fmt.Printf("PASS %s\n", name)
	} else {
		fails++
		fmt.Printf("FAIL %s: %s\n", name, detail)
	}
}

func must(err error) {
	if err != nil {
		fmt.Println("FATAL", err)
		os.Exit(2)
	}
}

type simTPM struct{ rw io.ReadWriteCloser }

func (t *simTPM) Send(in []byte) ([]byte, error) { return tpmutil.RunCommandRaw(t.rw, in) }
func (t *simTPM) Close() error                    { return t.rw.Close() }

func ekName(rwc transport.TPMCloser) string {
	h, _, err := attest.ReadEKCert(rwc)
	must(err)
	keyfile.FlushHandle(rwc, h)
	return fmt.Sprintf("%x", h.Name.Buffer)
}

// ca starts a CA whose key is in caTPM, trusting roots for EK certificates.
func ca(caTPM transport.TPMCloser, roots, inters string, users ...*server.UsersConf) (*httptest.Server, ssh.PublicKey) {
	k, err := keyfile.NewLoadableKey(caTPM, tpm2.TPMAlgECC, 256, []byte(""))
	must(err)
	pub, err := (&key.SSHTPMKey{TPMKey: k}).SSHPublicKey()
	must(err)
	as, err := server.NewTPMAttestServer(caTPM, &server.Config{
		EKRoots: roots, EKIntermediates: inters,
		Hosts: []*server.HostConf{{Host: "test.local", CaFile: &server.UnmarshalTPMkey{TPMKey: k}, Users: users}},
	})
	must(err)
	return httptest.NewServer(as.Handlers()), pub
}

func user(name, ek string) *server.UsersConf {
	return &server.UsersConf{User: name, EK: ek, OIDCConnector: "none"}
}

func params(rwc transport.TPMCloser, u string) *attest.AttestationParameters {
	k, rsp, err := keyfile.NewLoadableKeyWithResponse(rwc, tpm2.TPMAlgECC, 256, []byte(""))
	must(err)
	ap, err := attest.NewAttestationParameters(rwc, k, rsp)
	must(err)
	keyfile.FlushHandle(rwc, ap.Handle.Handle)
	ap.Host, ap.User = "test.local", u
	return ap
}

func post(url string, v any) string {
	b, _ := json.Marshal(v)
	rsp, err := http.Post(url, "application/json", bytes.NewBuffer(b))
	must(err)
	out, _ := io.ReadAll(rsp.Body)
	return string(out)
}

func main() {
	out, roots, inters, other := os.Args[1], os.Args[2], os.Args[3], os.Args[4]
	tpm, err := transport.OpenTPM("/dev/tpmrm0")
	must(err)
	defer tpm.Close()
	realEK := ekName(tpm)
	realCert, err := attest.ReadEKCertificate(tpm)
	must(err)
	fmt.Printf("real TPM: EK name %s..., EK certificate %d bytes\n", realEK[:16], len(realCert))

	s, err := ssim.GetWithFixedSeedInsecure(1234)
	must(err)
	sim := &simTPM{s}
	defer sim.Close()
	// TPM_EH_AUTH applies to every TPM in this process: give the throwaway simulator the same.
	if pw := os.Getenv("TPM_EH_AUTH"); pw != "" {
		_, err := tpm2.HierarchyChangeAuth{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHEndorsement, Auth: tpm2.PasswordAuth(nil)},
			NewAuth:    tpm2.TPM2BAuth{Buffer: []byte(pw)},
		}.Execute(sim)
		must(err)
	}
	simEK := ekName(sim)

	srv, caPub := ca(tpm, roots, inters, user("alice", realEK), user("mallory", "000b"+strings.Repeat("00", 32)), user("sim", simEK))
	defer srv.Close()
	must(os.WriteFile(filepath.Join(out, "ca.pub"), ssh.MarshalAuthorizedKey(caPub), 0o644))
	c := client.NewClient(srv.URL)

	// P1: real TPM, EK certificate chains to STMicroelectronics -> certificate
	uk, cert, err := c.GetKey(tpm, "alice", "test.local")
	check("P1 real TPM with STMicro EK certificate gets an SSH certificate", err == nil && cert != nil, fmt.Sprint(err))
	if err == nil {
		var buf bytes.Buffer
		must(keyfile.Encode(&buf, uk))
		must(os.WriteFile(filepath.Join(out, "id_ecdsa.tpm"), buf.Bytes(), 0o600))
		must(os.WriteFile(filepath.Join(out, "id_ecdsa-cert.pub"), ssh.MarshalAuthorizedKey(cert), 0o644))
	}

	// N1: real TPM, EK not the one listed for the user
	body := post(srv.URL+"/attest", params(tpm, "mallory"))
	check("N1 EK not listed for user -> rejected", strings.Contains(body, "invalid user"), body)

	// N2: credential secret not decrypted by the TPM
	var ch attest.EncryptedCredential
	must(json.Unmarshal([]byte(post(srv.URL+"/attest", params(tpm, "alice"))), &ch))
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	body = post(srv.URL+"/submit", client.ChallengeResponse{Secret: secret})
	check("N2 wrong credential secret -> no certificate", !strings.Contains(body, "SignedSSHCert"), body)

	// N3: SSH key public area changed after certification
	ap := params(tpm, "alice")
	ap.TPMBoundKey.Public.ObjectAttributes.UserWithAuth = !ap.TPMBoundKey.Public.ObjectAttributes.UserWithAuth
	body = post(srv.URL+"/attest", ap)
	check("N3 tampered key -> rejected", strings.Contains(body, "did not validate"), body)

	// N4: software TPM, EK name listed, no EK certificate (accepted before this change)
	_, _, err = c.GetKey(sim, "sim", "test.local")
	body = post(srv.URL+"/attest", params(sim, "sim"))
	check("N4 software TPM with listed EK -> rejected (no EK certificate)",
		err != nil && strings.Contains(body, "no EK certificate"), body)

	// N5: software TPM presenting the real TPM's EK certificate
	ap = params(sim, "sim")
	ap.EKCert = realCert
	body = post(srv.URL+"/attest", ap)
	check("N5 software TPM replaying the real EK certificate -> rejected",
		strings.Contains(body, "for another key than the challenged EK"), body)

	// N6: real TPM, but the CA trusts another manufacturer only
	srv2, _ := ca(tpm, other, "", user("alice", realEK))
	defer srv2.Close()
	body = post(srv2.URL+"/attest", params(tpm, "alice"))
	check("N6 CA trusting only Infineon -> real STMicro TPM rejected",
		strings.Contains(body, "does not chain to a trusted TPM manufacturer"), body)

	if fails > 0 {
		os.Exit(1)
	}
}
