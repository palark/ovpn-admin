package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeTestCert creates a self-signed certificate with the given extended key usages and returns
// its serial in index.txt form (upper case hex) and its PEM encoding.
func writeTestCert(t *testing.T, cn string, serial int64, usages ...x509.ExtKeyUsage) (string, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  usages,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%X", serial), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// setupServerCertPKI lays out an easy-rsa PKI like build-server-full / build-client-full do.
func setupServerCertPKI(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	pki := filepath.Join(dir, "pki")
	for _, sub := range []string{"certs_by_serial", "revoked/certs_by_serial", "issued"} {
		if err := os.MkdirAll(filepath.Join(pki, sub), 0755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path string, data []byte) {
		t.Helper()
		// easy-rsa issued/*.crt may start with the text form of the certificate
		if err := os.WriteFile(filepath.Join(pki, path), append([]byte("Certificate:\n    Data: ...\n"), data...), 0644); err != nil {
			t.Fatal(err)
		}
	}

	ovpn01, ovpn01PEM := writeTestCert(t, "ovpn01", 0x1A2B, x509.ExtKeyUsageServerAuth)
	write("certs_by_serial/"+ovpn01+".pem", ovpn01PEM)
	alice, alicePEM := writeTestCert(t, "alice", 0x1A2C, x509.ExtKeyUsageClientAuth)
	write("certs_by_serial/"+alice+".pem", alicePEM)
	both, bothPEM := writeTestCert(t, "both", 0x1A2D, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
	write("certs_by_serial/"+both+".pem", bothPEM)
	bob, bobPEM := writeTestCert(t, "bob", 0x1A2E, x509.ExtKeyUsageClientAuth)
	write("revoked/certs_by_serial/"+bob+".crt", bobPEM)
	// only issued/<CN>.crt is there
	merida, meridaPEM := writeTestCert(t, "merida", 0x1A2F, x509.ExtKeyUsageServerAuth)
	write("issued/merida.crt", meridaPEM)
	// issued/carol.crt belongs to a newer certificate with another serial
	_, newerPEM := writeTestCert(t, "carol", 0x1B00, x509.ExtKeyUsageServerAuth)
	write("issued/carol.crt", newerPEM)

	index := strings.Join([]string{
		"V\t351231235959Z\t\t" + ovpn01 + "\tunknown\t/CN=ovpn01",
		"V\t351231235959Z\t\t" + alice + "\tunknown\t/CN=alice",
		"V\t351231235959Z\t\t" + both + "\tunknown\t/CN=both",
		"R\t351231235959Z\t250101000000Z\t" + bob + "\tunknown\t/CN=bob",
		"V\t351231235959Z\t\t" + merida + "\tunknown\t/CN=merida",
		"V\t351231235959Z\t\t1A30\tunknown\t/CN=carol",
		"V\t351231235959Z\t\t01\tunknown\t/CN=server",
		"V\t351231235959Z\t\t../../x\tunknown\t/CN=evil",
	}, "\n") + "\n"
	indexPath := filepath.Join(pki, "index.txt")
	if err := os.WriteFile(indexPath, []byte(index), 0644); err != nil {
		t.Fatal(err)
	}

	setFlag(t, easyrsaDirPath, dir)
	setFlag(t, indexTxtPath, indexPath)
	serverCertCache.Clear()
	t.Cleanup(serverCertCache.Clear)
}

func TestIsServerCertificate(t *testing.T) {
	setupServerCertPKI(t)

	want := map[string]bool{
		"ovpn01": true,  // serverAuth (build-server-full), found by serial
		"alice":  false, // clientAuth
		"both":   false, // serverAuth + clientAuth (build-serverClient-full) can be a user
		"bob":    false, // revoked client, found in revoked/certs_by_serial
		"merida": true,  // found in issued/<CN>.crt
		"carol":  false, // issued/carol.crt has another serial, own certificate not found
		"server": true,  // CN "server" is always a server certificate
		"evil":   false, // serial with path characters is not used as a file name
	}
	for _, line := range indexTxtParser(fRead(*indexTxtPath)) {
		if got := isServerCertificate(line); got != want[line.Identity] {
			t.Errorf("isServerCertificate(%s) = %v, want %v", line.Identity, got, want[line.Identity])
		}
	}
}

func TestUsersListHidesServerCertificates(t *testing.T) {
	setupServerCertPKI(t)

	var got []string
	for _, u := range (&OvpnAdmin{}).usersList() {
		got = append(got, u.Identity+":"+u.AccountStatus)
	}
	want := "alice:Active both:Active bob:Revoked carol:Active evil:Active"
	if strings.Join(got, " ") != want {
		t.Errorf("usersList() = %v, want %s", got, want)
	}
}

func TestServerCertificatesAreNotManaged(t *testing.T) {
	setupServerCertPKI(t)

	for _, cn := range []string{"ovpn01", "merida", "server"} {
		if checkUserExist(cn) {
			t.Errorf("checkUserExist(%q) = true, server certificates must not be managed as users", cn)
		}
		if !checkCommonNameExist(cn) {
			t.Errorf("checkCommonNameExist(%q) = false, a user must not reuse the CN of a server certificate", cn)
		}
	}
	if !checkUserExist("alice") {
		t.Error(`checkUserExist("alice") = false`)
	}

	if err, _ := (&OvpnAdmin{}).userRevoke("ovpn01"); err == nil {
		t.Error(`userRevoke("ovpn01") succeeded for a server certificate`)
	}
}
