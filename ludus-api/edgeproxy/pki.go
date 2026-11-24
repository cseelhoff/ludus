package edgeproxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	enrollDomainCSR  = "ludus-edge-enroll-csr-v1:"
	enrollDomainSeal = "ludus-edge-enroll-seal-v1:"
)

// ControlPlanePKI stores the CA, ludus-client mTLS credentials, and one-time Ed25519 enrollment keypair
// persisted on the Ludus control plane (/opt/ludus/db/edge/).
// Security invariant: edge-server's TLS private key and wg0's ServerPrivateKey are generated locally
// inside ludus-edge during first-boot enrollment and NEVER exist on Ludus or cross the network.
type ControlPlanePKI struct {
	CACertPEM       []byte
	CAKeyPEM        []byte
	ClientCertPEM   []byte
	ClientKeyPEM    []byte
	EnrollPublicB64 string
	EnrollPrivB64   string
}

// EnrollCSRRequest is sent by Ludus to an unsealed ludus-edge to request its locally generated CSR + WG public key.
type EnrollCSRRequest struct {
	Nonce     string `json:"nonce"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
}

// EnrollCSRResponse is returned by ludus-edge with its locally generated TLS CSR and WireGuard server public key.
// Zero private keys are included.
type EnrollCSRResponse struct {
	EdgeCSRPEM          string `json:"edge_csr_pem"`
	WGServerPublicKey   string `json:"wg_server_public_key"`
	AlreadySealed       bool   `json:"already_sealed,omitempty"`
}

// WireGuardPeerPublicEntry represents one static client peer on ludus-edge's wg0 interface (public key + /32 IP only).
type WireGuardPeerPublicEntry struct {
	Slot      int    `json:"slot"`
	PublicKey string `json:"public_key"`
}

// EnrollSealPayload contains ONLY public certificates and WireGuard client public keys signed by EnrollPrivateKey.
type EnrollSealPayload struct {
	Timestamp        int64                      `json:"timestamp"`
	CACertPEM        string                     `json:"ca_cert_pem"`
	ServerCertPEM    string                     `json:"server_cert_pem"`
	WGListenPort     int                        `json:"wg_listen_port"`
	WGPeers          []WireGuardPeerPublicEntry `json:"wg_peers"`
}

// EnrollSealRequest wraps the JSON-serialized EnrollSealPayload and its Ed25519 signature.
type EnrollSealRequest struct {
	PayloadJSON string `json:"payload_json"`
	Signature   string `json:"signature"`
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

// EnsureControlPlanePKI loads or generates the Ludus-side mTLS CA, client leaf certificate, and Ed25519 enrollment keypair.
func EnsureControlPlanePKI(stateDir string) (*ControlPlanePKI, error) {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("creating edge state dir %s: %w", stateDir, err)
	}

	caCertPath := filepath.Join(stateDir, "ca.crt")
	caKeyPath := filepath.Join(stateDir, "ca.key")
	clientCertPath := filepath.Join(stateDir, "client.crt")
	clientKeyPath := filepath.Join(stateDir, "client.key")
	enrollKeyPath := filepath.Join(stateDir, "enroll_ed25519.json")

	type enrollKeyDisk struct {
		PublicB64  string `json:"public_b64"`
		PrivateB64 string `json:"private_b64"`
	}

	if allFilesExist(caCertPath, caKeyPath, clientCertPath, clientKeyPath, enrollKeyPath) {
		caCert, err1 := os.ReadFile(caCertPath)
		caKey, err2 := os.ReadFile(caKeyPath)
		clientCert, err3 := os.ReadFile(clientCertPath)
		clientKey, err4 := os.ReadFile(clientKeyPath)
		enrollRaw, err5 := os.ReadFile(enrollKeyPath)
		if err1 == nil && err2 == nil && err3 == nil && err4 == nil && err5 == nil {
			var ek enrollKeyDisk
			if err := json.Unmarshal(enrollRaw, &ek); err == nil && ek.PublicB64 != "" && ek.PrivateB64 != "" {
				return &ControlPlanePKI{
					CACertPEM:       caCert,
					CAKeyPEM:        caKey,
					ClientCertPEM:   clientCert,
					ClientKeyPEM:    clientKey,
					EnrollPublicB64: ek.PublicB64,
					EnrollPrivB64:   ek.PrivateB64,
				}, nil
			}
		}
	}

	now := time.Now().UTC()
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating CA Ed25519 key: %w", err)
	}
	caSerial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "ludus-edge-ca", Organization: []string{"Ludus"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caPub, caPriv)
	if err != nil {
		return nil, fmt.Errorf("creating CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caKeyDER, err := x509.MarshalPKCS8PrivateKey(caPriv)
	if err != nil {
		return nil, err
	}
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: caKeyDER})

	// Issue ludus-client mTLS certificate.
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating client Ed25519 key: %w", err)
	}
	clientSerial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	clientTmpl := &x509.Certificate{
		SerialNumber: clientSerial,
		Subject:      pkix.Name{CommonName: "ludus-controller", Organization: []string{"Ludus"}},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(5 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTmpl, caCert, clientPub, caPriv)
	if err != nil {
		return nil, fmt.Errorf("creating client certificate: %w", err)
	}
	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	clientKeyDER, err := x509.MarshalPKCS8PrivateKey(clientPriv)
	if err != nil {
		return nil, err
	}
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clientKeyDER})

	// Generate Ed25519 enrollment keypair (only EnrollPublicB64 goes to Proxmox cidata).
	enrollPub, enrollPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating enrollment Ed25519 key: %w", err)
	}
	ek := enrollKeyDisk{
		PublicB64:  base64.StdEncoding.EncodeToString(enrollPub),
		PrivateB64: base64.StdEncoding.EncodeToString(enrollPriv),
	}
	ekBytes, err := json.MarshalIndent(ek, "", "  ")
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile(caCertPath, caCertPEM, 0644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(caKeyPath, caKeyPEM, 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(clientCertPath, clientCertPEM, 0644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(clientKeyPath, clientKeyPEM, 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(enrollKeyPath, append(ekBytes, '\n'), 0600); err != nil {
		return nil, err
	}

	return &ControlPlanePKI{
		CACertPEM:       caCertPEM,
		CAKeyPEM:        caKeyPEM,
		ClientCertPEM:   clientCertPEM,
		ClientKeyPEM:    clientKeyPEM,
		EnrollPublicB64: ek.PublicB64,
		EnrollPrivB64:   ek.PrivateB64,
	}, nil
}

// SignEdgeServerCSR signs a CSR generated locally on ludus-edge, attaching the configured IP and DNS SANs.
func (p *ControlPlanePKI) SignEdgeServerCSR(csrPEM []byte, edgeIP string) ([]byte, error) {
	csrBlock, _ := pem.Decode(csrPEM)
	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("verifying CSR signature: %w", err)
	}

	caCertBlock, _ := pem.Decode(p.CACertPEM)
	if caCertBlock == nil {
		return nil, fmt.Errorf("invalid CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, err
	}
	caKeyBlock, _ := pem.Decode(p.CAKeyPEM)
	if caKeyBlock == nil {
		return nil, fmt.Errorf("invalid CA key PEM")
	}
	caPrivAny, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	caPriv, ok := caPrivAny.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("CA private key is not Ed25519")
	}

	ips := []net.IP{net.ParseIP("127.0.0.1")}
	if parsed := net.ParseIP(strings.TrimSpace(edgeIP)); parsed != nil {
		ips = append(ips, parsed)
	}
	for _, ip := range csr.IPAddresses {
		ips = append(ips, ip)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "ludus-edge", Organization: []string{"Ludus"}},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(5 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"ludus-edge", "localhost"},
		IPAddresses:  ips,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, csr.PublicKey, caPriv)
	if err != nil {
		return nil, fmt.Errorf("signing edge server certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), nil
}

// BuildClientTLSConfig builds a TLS 1.3 mTLS client configuration from PEM files on disk.
func BuildClientTLSConfig(caFile, certFile, keyFile, serverName string) (*tls.Config, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("reading edge CA %s: %w", caFile, err)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading edge client keypair (%s, %s): %w", certFile, keyFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate from %s", caFile)
	}
	if strings.TrimSpace(serverName) == "" {
		serverName = "ludus-edge"
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		ServerName:   serverName,
	}, nil
}

func signEnrollMessage(privB64 string, domain string, body []byte) (string, error) {
	privRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privB64))
	if err != nil || len(privRaw) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid Ed25519 enrollment private key")
	}
	digest := sha256.Sum256(append([]byte(domain), body...))
	sig := ed25519.Sign(ed25519.PrivateKey(privRaw), digest[:])
	return base64.StdEncoding.EncodeToString(sig), nil
}

func verifyEnrollMessage(pubB64 string, domain string, body []byte, sigB64 string) error {
	pubRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubB64))
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid Ed25519 enrollment public key")
	}
	sigRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil || len(sigRaw) != ed25519.SignatureSize {
		return fmt.Errorf("invalid Ed25519 signature encoding")
	}
	digest := sha256.Sum256(append([]byte(domain), body...))
	if !ed25519.Verify(ed25519.PublicKey(pubRaw), digest[:], sigRaw) {
		return fmt.Errorf("enrollment Ed25519 signature verification failed")
	}
	return nil
}

func allFilesExist(paths ...string) bool {
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil || st.IsDir() {
			return false
		}
	}
	return true
}

// FormatEnrollSSHAuthorizedKey encodes the 32-byte Ed25519 enrollment public key as a standard
// RFC 8709 OpenSSH ssh-ed25519 authorized_keys line ("ssh-ed25519 AAAA... ludus-edge-enroll")
// so non-root Proxmox API tokens can inject it natively via standard VM.Config.Cloudinit sshkeys
// without requiring root-only cicustom snippets.
func FormatEnrollSSHAuthorizedKey(enrollPubB64 string) (string, error) {
	pubRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(enrollPubB64))
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid Ed25519 enrollment public key")
	}
	sshPub, err := ssh.NewPublicKey(ed25519.PublicKey(pubRaw))
	if err != nil {
		return "", fmt.Errorf("converting Ed25519 enrollment key to OpenSSH format: %w", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " ludus-edge-enroll", nil
}

// ParseEnrollSSHAuthorizedKey extracts the 32-byte Ed25519 enrollment public key (base64)
// from a cloud-init authorized_keys file or raw base64 string.
func ParseEnrollSSHAuthorizedKey(text string) (string, error) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return "", fmt.Errorf("empty enrollment public key input")
	}
	// Support raw base64 32-byte Ed25519 key directly as well.
	if raw, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(raw) == ed25519.PublicKeySize {
		return base64.StdEncoding.EncodeToString(raw), nil
	}
	for _, line := range strings.Split(trimmed, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pubKey, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			continue
		}
		if comment != "" && comment != "ludus-edge-enroll" && !strings.Contains(comment, "ludus-edge") {
			continue
		}
		cryptoPub, ok := pubKey.(ssh.CryptoPublicKey)
		if !ok {
			continue
		}
		edPub, ok := cryptoPub.CryptoPublicKey().(ed25519.PublicKey)
		if !ok || len(edPub) != ed25519.PublicKeySize {
			continue
		}
		return base64.StdEncoding.EncodeToString(edPub), nil
	}
	return "", fmt.Errorf("no valid ludus-edge Ed25519 enrollment public key found")
}
