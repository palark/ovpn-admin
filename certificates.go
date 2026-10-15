package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// decode certificate from PEM to x509
func decodeCert(certPEMBytes []byte) (cert *x509.Certificate, err error) {
	certPem, _ := pem.Decode(certPEMBytes)
	if certPem == nil {
		return nil, errors.New("error decode certificate PEM")
	}
	certPemBytes := certPem.Bytes

	cert, err = x509.ParseCertificate(certPemBytes)
	if err != nil {
		return
	}

	return
}

// decode private key from PEM to RSA format
func decodePrivKey(privKey []byte) (key *rsa.PrivateKey, err error) {
	privKeyPem, _ := pem.Decode(privKey)
	if privKeyPem == nil {
		return nil, errors.New("error decode private key PEM")
	}
	key, err = x509.ParsePKCS1PrivateKey(privKeyPem.Bytes)
	if err == nil {
		return
	}

	tmp, err := x509.ParsePKCS8PrivateKey(privKeyPem.Bytes)
	if err != nil {
		err = errors.New("error parse private key")
		return
	}
	key, _ = tmp.(*rsa.PrivateKey)

	return
}

// return PEM encoded private key
func genPrivKey() (privKeyPEM *bytes.Buffer, err error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)

	//privKeyPKCS1 := x509.MarshalPKCS1PrivateKey(privKey)

	privKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return
	}

	privKeyPEM = new(bytes.Buffer)
	err = pem.Encode(privKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyPKCS8,
	})

	return
}

// return PEM encoded certificate
func genCA(privKey *rsa.PrivateKey) (issuerPEM *bytes.Buffer, err error) {
	serialNumberRange := new(big.Int).Lsh(big.NewInt(1), 128)

	issuerSerial, err := rand.Int(rand.Reader, serialNumberRange)

	issuerTemplate := x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		SerialNumber:          issuerSerial,
		Subject: pkix.Name{
			CommonName: "ca",
		},

		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
	}
	issuerBytes, err := x509.CreateCertificate(rand.Reader, &issuerTemplate, &issuerTemplate, &privKey.PublicKey, privKey)
	if err != nil {
		return
	}

	issuerPEM = new(bytes.Buffer)
	_ = pem.Encode(issuerPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: issuerBytes,
	})

	return
}

// return PEM encoded certificate
func genServerCert(privKey, caPrivKey *rsa.PrivateKey, ca *x509.Certificate, cn string) (issuerPEM *bytes.Buffer, err error) {
	serialNumberRange := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialNumberRange)

	template := x509.Certificate{
		BasicConstraintsValid: true,
		DNSNames:              []string{cn},
		SerialNumber:          serial,
		Subject: pkix.Name{
			CommonName: cn,
		},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:   time.Now(),
		NotAfter:    ca.NotAfter,
	}

	issuerBytes, err := x509.CreateCertificate(rand.Reader, &template, ca, &privKey.PublicKey, caPrivKey)
	if err != nil {
		return
	}

	issuerPEM = new(bytes.Buffer)
	_ = pem.Encode(issuerPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: issuerBytes,
	})

	return
}

// return PEM encoded certificate
func genClientCert(privKey, caPrivKey *rsa.PrivateKey, ca *x509.Certificate, cn string) (issuerPEM *bytes.Buffer, err error) {
	serialNumberRange := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialNumberRange)

	certLifetimeDays, err := strconv.Atoi(*clientCertExpirationDays)
	if err != nil {
		return nil, fmt.Errorf("can't get client certificate expiration value: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(certLifetimeDays) * 24 * time.Hour)
	if notAfter.After(ca.NotAfter) {
		notAfter = ca.NotAfter
	}

	template := x509.Certificate{
		BasicConstraintsValid: true,
		DNSNames:              []string{cn},
		SerialNumber:          serial,
		Subject: pkix.Name{
			CommonName: cn,
		},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
	}

	issuerBytes, err := x509.CreateCertificate(rand.Reader, &template, ca, &privKey.PublicKey, caPrivKey)
	if err != nil {
		return
	}

	issuerPEM = new(bytes.Buffer)
	_ = pem.Encode(issuerPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: issuerBytes,
	})

	return
}

// return PEM encoded CRL
func genCRL(certs []*RevokedCert, ca *x509.Certificate, caKey *rsa.PrivateKey) (crlPEM *bytes.Buffer, err error) {
	var revokedCertificates []pkix.RevokedCertificate

	for _, cert := range certs {
		revokedCertificates = append(revokedCertificates, pkix.RevokedCertificate{SerialNumber: cert.Cert.SerialNumber, RevocationTime: cert.RevokedTime})
	}

	revocationList := &x509.RevocationList{
		//SignatureAlgorithm: x509.SHA256WithRSA,
		RevokedCertificates: revokedCertificates,
		Number:              big.NewInt(1),
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(180 * time.Hour * 24),
		//ExtraExtensions: []pkix.Extension{},
	}

	crl, err := x509.CreateRevocationList(rand.Reader, revocationList, ca, caKey)
	if err != nil {
		return nil, err
	}

	crlPEM = new(bytes.Buffer)
	err = pem.Encode(crlPEM, &pem.Block{
		Type:  "X509 CRL",
		Bytes: crl,
	})
	if err != nil {
		return
	}

	return
}

var (
	serverCertCache   sync.Map // index.txt serial -> bool
	indexSerialRegexp = regexp.MustCompile(`^[0-9A-Fa-f]+$`)
)

// isServerCertificate reports whether the certificate of an index.txt line is an OpenVPN server
// certificate: extended key usage serverAuth without clientAuth, as "easyrsa build-server-full"
// issues it (whatever its CN is, e.g. the host name). Server certificates are neither listed nor
// managed as users. The CN "server" (the server certificate of kubernetes.secrets) is always one.
func isServerCertificate(line indexTxtLine) bool {
	if line.Identity == "server" {
		return true
	}
	if v, ok := serverCertCache.Load(line.SerialNumber); ok {
		return v.(bool)
	}

	cert := readIndexTxtCertificate(line)
	if cert == nil {
		// not cached: the file may appear later (e.g. a slave before its first sync)
		return false
	}
	server := slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) &&
		!slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	serverCertCache.Store(line.SerialNumber, server)
	return server
}

// readIndexTxtCertificate reads the certificate of an index.txt line from the easy-rsa PKI:
// certs_by_serial/<serial>.pem, revoked/certs_by_serial/<serial>.crt or issued/<CN>.crt
// (the last one only if it has the same serial, a newer certificate may have the same CN).
func readIndexTxtCertificate(line indexTxtLine) *x509.Certificate {
	if !indexSerialRegexp.MatchString(line.SerialNumber) {
		return nil
	}
	serial, ok := new(big.Int).SetString(line.SerialNumber, 16)
	if !ok {
		return nil
	}

	pki := filepath.Join(*easyrsaDirPath, "pki")
	paths := []string{
		filepath.Join(pki, "certs_by_serial", strings.ToUpper(line.SerialNumber)+".pem"),
		filepath.Join(pki, "revoked", "certs_by_serial", strings.ToUpper(line.SerialNumber)+".crt"),
	}
	if usernameIsPathSafe(line.Identity) {
		paths = append(paths, filepath.Join(pki, "issued", line.Identity+".crt"))
	}

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		cert, err := decodeCert(data)
		if err != nil || cert.SerialNumber.Cmp(serial) != 0 {
			continue
		}
		return cert
	}
	return nil
}
