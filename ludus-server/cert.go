package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/user"
	"strconv"
	"time"
)

func generateSelfSignedCert() {
	certFile := ludusInstallPath + "/cert.pem"
	keyFile := ludusInstallPath + "/key.pem"
	// Check if the cert and key already exist
	if fileExists(certFile) && fileExists(keyFile) {
		return
	}

	// Generate a new RSA key
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Create a self-signed certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Ludus Self-Signed Cert"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Create the certificate
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)

	// Save the certificate (0644) and private key (0640, readable by group "ludus" so both
	// ludus-admin.service [root] and ludus.service [ludus] can serve HTTPS regardless of umask).
	certOut, err := os.OpenFile(certFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err == nil {
		_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		_ = certOut.Close()
		_ = os.Chmod(certFile, 0644)
	}

	keyOut, err := os.OpenFile(keyFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err == nil {
		_ = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
		_ = keyOut.Close()
		_ = os.Chmod(keyFile, 0640)
	}

	if os.Geteuid() == 0 {
		if grp, grpErr := user.LookupGroup("ludus"); grpErr == nil {
			if gid, parseErr := strconv.Atoi(grp.Gid); parseErr == nil {
				_ = os.Chown(certFile, 0, gid)
				_ = os.Chown(keyFile, 0, gid)
			}
		}
	}
}
