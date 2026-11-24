package edgeproxy

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/curve25519"
)

// ServerConfig configures the ludus-edge-proxy daemon on ludus-edge.
type ServerConfig struct {
	ListenAddr        string // e.g. "0.0.0.0:8444"
	StateDir          string // e.g. "/var/lib/ludus-edge" (private 0600 disk)
	EnrollPublicB64   string // Ed25519 enrollment public key from cloud-init cidata
	NATBindIP         string // IP to bind reverse Packer listeners on (default "192.0.2.254")
	PackerPortMin     uint16 // default 8350
	PackerPortMax     uint16 // default 8399
	DialTimeout       time.Duration
	EnableWGQuickHook bool // When true on Alpine ludus-edge, writes /etc/wireguard/wg0.conf and reloads wg0 on seal
	DialTarget        func(ap netip.AddrPort, timeout time.Duration) (net.Conn, error)
	Logger            *slog.Logger
}

type pendingReverseConn struct {
	conn      net.Conn
	expiresAt time.Time
}

type reversePortSession struct {
	port    uint16
	ln      net.Listener
	mu      sync.Mutex
	pending map[uint64]pendingReverseConn
}

// Server implements the mTLS 1.3 range transport & Packer reverse listener proxy on ludus-edge.
type Server struct {
	cfg               ServerConfig
	log               *slog.Logger
	listener          net.Listener
	unsealedTLSConfig *tls.Config
	sealedTLS         atomic.Pointer[tls.Config]

	enrollMu sync.Mutex

	revMu      sync.Mutex
	revPorts   map[uint16]*reversePortSession
	nextConnID atomic.Uint64
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

type halfCloser interface {
	CloseWrite() error
}

func pipeBidirectional(a net.Conn, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	copyOne := func(dst net.Conn, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if hc, ok := dst.(halfCloser); ok {
			_ = hc.CloseWrite()
		} else {
			_ = dst.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		}
	}
	go copyOne(a, b)
	go copyOne(b, a)
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

// NewServer constructs and initializes a Server, loading sealed mTLS state if already present on disk.
func NewServer(cfg ServerConfig) (*Server, error) {
	if strings.TrimSpace(cfg.ListenAddr) == "" {
		cfg.ListenAddr = "0.0.0.0:8444"
	}
	if strings.TrimSpace(cfg.StateDir) == "" {
		cfg.StateDir = "/var/lib/ludus-edge"
	}
	if strings.TrimSpace(cfg.NATBindIP) == "" {
		cfg.NATBindIP = DefaultEdgeNATIP
	}
	if cfg.PackerPortMin == 0 {
		cfg.PackerPortMin = DefaultPackerPortMin
	}
	if cfg.PackerPortMax == 0 {
		cfg.PackerPortMax = DefaultPackerPortMax
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 15 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if err := os.MkdirAll(cfg.StateDir, 0700); err != nil {
		return nil, fmt.Errorf("creating edge state dir %s: %w", cfg.StateDir, err)
	}

	ephemTLS, err := buildEphemeralUnsealedTLS()
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:               cfg,
		log:               cfg.Logger,
		unsealedTLSConfig: ephemTLS,
		revPorts:          make(map[uint16]*reversePortSession),
	}

	if s.isSealedOnDisk() {
		sealedCfg, err := s.loadSealedServerTLS()
		if err != nil {
			return nil, fmt.Errorf("loading sealed mTLS credentials: %w", err)
		}
		s.sealedTLS.Store(sealedCfg)
	}
	return s, nil
}

func buildEphemeralUnsealedTLS() (*tls.Config, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "ludus-edge-unsealed"},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"ludus-edge", "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{tlsCert},
		ClientAuth:   tls.NoClientCert,
	}, nil
}

func (s *Server) isSealedOnDisk() bool {
	return allFilesExist(
		filepath.Join(s.cfg.StateDir, "sealed"),
		filepath.Join(s.cfg.StateDir, "ca.crt"),
		filepath.Join(s.cfg.StateDir, "server.crt"),
		filepath.Join(s.cfg.StateDir, "server.key"),
	)
}

func (s *Server) loadSealedServerTLS() (*tls.Config, error) {
	caPEM, err := os.ReadFile(filepath.Join(s.cfg.StateDir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("invalid CA cert in %s", s.cfg.StateDir)
	}
	cert, err := tls.LoadX509KeyPair(
		filepath.Join(s.cfg.StateDir, "server.crt"),
		filepath.Join(s.cfg.StateDir, "server.key"),
	)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}, nil
}

// IsSealed reports whether ludus-edge has completed one-time enrollment and is enforcing mTLS.
func (s *Server) IsSealed() bool {
	return s.sealedTLS.Load() != nil
}

// Start binds the TLS listener and begins serving connections asynchronously.
func (s *Server) Start() error {
	baseTLS := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			if sealed := s.sealedTLS.Load(); sealed != nil {
				return sealed, nil
			}
			return s.unsealedTLSConfig, nil
		},
	}
	rawLn, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.cfg.ListenAddr, err)
	}
	s.listener = tls.NewListener(rawLn, baseTLS)
	go s.acceptLoop()
	return nil
}

// Addr returns the bound listener address after Start().
func (s *Server) Addr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// Close stops the main listener and all active reverse Packer listeners.
func (s *Server) Close() error {
	s.revMu.Lock()
	for _, sess := range s.revPorts {
		_ = sess.ln.Close()
		sess.mu.Lock()
		for _, p := range sess.pending {
			_ = p.conn.Close()
		}
		sess.pending = nil
		sess.mu.Unlock()
	}
	s.revPorts = make(map[uint16]*reversePortSession)
	s.revMu.Unlock()

	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(rawConn net.Conn) {
	tlsConn, ok := rawConn.(*tls.Conn)
	if !ok {
		_ = rawConn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		_ = tlsConn.Close()
		return
	}

	state := tlsConn.ConnectionState()
	sealed := s.IsSealed()
	if sealed && len(state.VerifiedChains) == 0 {
		_ = tlsConn.Close()
		return
	}

	br := bufio.NewReaderSize(tlsConn, 4096)
	line, err := br.ReadString('\n')
	if err != nil {
		_ = tlsConn.Close()
		return
	}
	line = strings.TrimSpace(line)
	parts := strings.Fields(line)
	if len(parts) == 0 {
		_ = tlsConn.Close()
		return
	}
	cmd := parts[0]

	if !sealed {
		switch cmd {
		case "ENROLL_CSR":
			s.handleEnrollCSR(tlsConn, br)
		case "ENROLL_SEAL":
			s.handleEnrollSeal(tlsConn, br)
		default:
			_, _ = io.WriteString(tlsConn, "ERR edge node is unsealed\n")
			_ = tlsConn.Close()
		}
		return
	}

	// Clear handshake deadline now that client mTLS identity and command header were read.
	_ = tlsConn.SetDeadline(time.Time{})

	switch cmd {
	case "PING":
		_, _ = io.WriteString(tlsConn, "OK PONG\n")
		_ = tlsConn.Close()
	case "DIAL":
		if len(parts) != 2 {
			_, _ = io.WriteString(tlsConn, "ERR usage: DIAL <ip>:<port>\n")
			_ = tlsConn.Close()
			return
		}
		s.handleDial(&bufferedConn{Conn: tlsConn, r: br}, parts[1])
	case "LISTEN":
		if len(parts) != 2 {
			_, _ = io.WriteString(tlsConn, "ERR usage: LISTEN <port>\n")
			_ = tlsConn.Close()
			return
		}
		s.handleListen(tlsConn, parts[1])
	case "ACCEPT_JOIN":
		if len(parts) != 3 {
			_, _ = io.WriteString(tlsConn, "ERR usage: ACCEPT_JOIN <port> <conn_id>\n")
			_ = tlsConn.Close()
			return
		}
		s.handleAcceptJoin(&bufferedConn{Conn: tlsConn, r: br}, parts[1], parts[2])
	default:
		_, _ = io.WriteString(tlsConn, "ERR unknown command\n")
		_ = tlsConn.Close()
	}
}

func (s *Server) handleEnrollCSR(conn net.Conn, br *bufio.Reader) {
	defer conn.Close()
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()

	if s.IsSealed() {
		_, _ = io.WriteString(conn, "ERR already sealed\n")
		return
	}
	if strings.TrimSpace(s.cfg.EnrollPublicB64) == "" {
		_, _ = io.WriteString(conn, "ERR enrollment disabled (no enrollment public key)\n")
		return
	}

	bodyLine, err := br.ReadString('\n')
	if err != nil {
		return
	}
	var req EnrollCSRRequest
	if err := json.Unmarshal([]byte(bodyLine), &req); err != nil {
		_, _ = io.WriteString(conn, "ERR invalid ENROLL_CSR payload\n")
		return
	}
	if absInt64(time.Now().Unix()-req.Timestamp) > 300 {
		_, _ = io.WriteString(conn, "ERR enrollment timestamp skew exceeded\n")
		return
	}
	msg := fmt.Sprintf("%s|%d", req.Nonce, req.Timestamp)
	if err := verifyEnrollMessage(s.cfg.EnrollPublicB64, enrollDomainCSR, []byte(msg), req.Signature); err != nil {
		_, _ = io.WriteString(conn, "ERR "+err.Error()+"\n")
		return
	}

	csrPEM, wgPubB64, err := s.ensureLocalServerAndWGKeys()
	if err != nil {
		_, _ = io.WriteString(conn, "ERR generating local edge keys: "+err.Error()+"\n")
		return
	}

	respBytes, _ := json.Marshal(EnrollCSRResponse{
		EdgeCSRPEM:        string(csrPEM),
		WGServerPublicKey: wgPubB64,
	})
	_, _ = fmt.Fprintf(conn, "OK %s\n", string(respBytes))
}

func (s *Server) ensureLocalServerAndWGKeys() (csrPEM []byte, wgPubB64 string, err error) {
	serverKeyPath := filepath.Join(s.cfg.StateDir, "server.key")
	csrPath := filepath.Join(s.cfg.StateDir, "server.csr")
	wgPrivPath := filepath.Join(s.cfg.StateDir, "wg_server.key")
	wgPubPath := filepath.Join(s.cfg.StateDir, "wg_server.pub")

	if !allFilesExist(serverKeyPath, csrPath) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, "", err
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, "", err
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject:  pkix.Name{CommonName: "ludus-edge", Organization: []string{"Ludus"}},
			DNSNames: []string{"ludus-edge", "localhost"},
		}, priv)
		if err != nil {
			return nil, "", err
		}
		cPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
		if err := os.WriteFile(serverKeyPath, keyPEM, 0600); err != nil {
			return nil, "", err
		}
		if err := os.WriteFile(csrPath, cPEM, 0644); err != nil {
			return nil, "", err
		}
	}

	if !allFilesExist(wgPrivPath, wgPubPath) {
		var wgPriv [32]byte
		if _, err := rand.Read(wgPriv[:]); err != nil {
			return nil, "", err
		}
		wgPriv[0] &= 248
		wgPriv[31] &= 127
		wgPriv[31] |= 64
		wgPub, err := curve25519.X25519(wgPriv[:], curve25519.Basepoint)
		if err != nil {
			return nil, "", err
		}
		if err := os.WriteFile(wgPrivPath, []byte(base64.StdEncoding.EncodeToString(wgPriv[:])+"\n"), 0600); err != nil {
			return nil, "", err
		}
		if err := os.WriteFile(wgPubPath, []byte(base64.StdEncoding.EncodeToString(wgPub)+"\n"), 0644); err != nil {
			return nil, "", err
		}
	}

	csrPEM, err = os.ReadFile(csrPath)
	if err != nil {
		return nil, "", err
	}
	wgPubRaw, err := os.ReadFile(wgPubPath)
	if err != nil {
		return nil, "", err
	}
	return csrPEM, strings.TrimSpace(string(wgPubRaw)), nil
}

func (s *Server) handleEnrollSeal(conn net.Conn, br *bufio.Reader) {
	defer conn.Close()
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()

	if s.IsSealed() {
		_, _ = io.WriteString(conn, "ERR already sealed\n")
		return
	}
	if strings.TrimSpace(s.cfg.EnrollPublicB64) == "" {
		_, _ = io.WriteString(conn, "ERR enrollment disabled\n")
		return
	}

	bodyLine, err := br.ReadString('\n')
	if err != nil {
		return
	}
	var req EnrollSealRequest
	if err := json.Unmarshal([]byte(bodyLine), &req); err != nil {
		_, _ = io.WriteString(conn, "ERR invalid ENROLL_SEAL wrapper\n")
		return
	}
	if err := verifyEnrollMessage(s.cfg.EnrollPublicB64, enrollDomainSeal, []byte(req.PayloadJSON), req.Signature); err != nil {
		_, _ = io.WriteString(conn, "ERR "+err.Error()+"\n")
		return
	}

	var payload EnrollSealPayload
	if err := json.Unmarshal([]byte(req.PayloadJSON), &payload); err != nil {
		_, _ = io.WriteString(conn, "ERR invalid seal payload JSON\n")
		return
	}
	if absInt64(time.Now().Unix()-payload.Timestamp) > 300 {
		_, _ = io.WriteString(conn, "ERR seal timestamp skew exceeded\n")
		return
	}

	wgPrivBytes, err := os.ReadFile(filepath.Join(s.cfg.StateDir, "wg_server.key"))
	if err != nil {
		_, _ = io.WriteString(conn, "ERR ENROLL_CSR must be called before ENROLL_SEAL\n")
		return
	}

	caPath := filepath.Join(s.cfg.StateDir, "ca.crt")
	srvCertPath := filepath.Join(s.cfg.StateDir, "server.crt")
	wgConfPath := filepath.Join(s.cfg.StateDir, "wg0.conf")
	sealMarker := filepath.Join(s.cfg.StateDir, "sealed")

	if err := os.WriteFile(caPath, []byte(payload.CACertPEM), 0644); err != nil {
		_, _ = io.WriteString(conn, "ERR writing CA cert: "+err.Error()+"\n")
		return
	}
	if err := os.WriteFile(srvCertPath, []byte(payload.ServerCertPEM), 0644); err != nil {
		_, _ = io.WriteString(conn, "ERR writing server cert: "+err.Error()+"\n")
		return
	}

	listenPort := payload.WGListenPort
	if listenPort <= 0 {
		listenPort = 51820
	}
	var wgBuf strings.Builder
	fmt.Fprintf(&wgBuf, "[Interface]\nAddress = 198.51.100.1/24\nListenPort = %d\nPrivateKey = %s\n",
		listenPort, strings.TrimSpace(string(wgPrivBytes)))
	for _, peer := range payload.WGPeers {
		if peer.Slot < 2 || peer.Slot > 254 || strings.TrimSpace(peer.PublicKey) == "" {
			continue
		}
		fmt.Fprintf(&wgBuf, "\n[Peer]\nPublicKey = %s\nAllowedIPs = 198.51.100.%d/32\n",
			strings.TrimSpace(peer.PublicKey), peer.Slot)
	}
	if err := os.WriteFile(wgConfPath, []byte(wgBuf.String()), 0600); err != nil {
		_, _ = io.WriteString(conn, "ERR writing wg0.conf: "+err.Error()+"\n")
		return
	}

	// Verify the signed server certificate pairs cleanly with our locally generated server.key BEFORE sealing.
	sealedCfg, err := s.loadSealedServerTLS()
	if err != nil {
		_, _ = io.WriteString(conn, "ERR validating sealed TLS keypair: "+err.Error()+"\n")
		return
	}

	if s.cfg.EnableWGQuickHook {
		_ = os.MkdirAll("/etc/wireguard", 0700)
		if copyErr := os.WriteFile("/etc/wireguard/wg0.conf", []byte(wgBuf.String()), 0600); copyErr == nil {
			_ = exec.Command("wg-quick", "down", "wg0").Run()
			if out, upErr := exec.Command("wg-quick", "up", "wg0").CombinedOutput(); upErr != nil {
				s.log.Warn("wg-quick up wg0 returned warning", "err", upErr, "output", string(out))
			}
		}
	}

	if err := os.WriteFile(sealMarker, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0600); err != nil {
		_, _ = io.WriteString(conn, "ERR writing seal marker: "+err.Error()+"\n")
		return
	}

	s.sealedTLS.Store(sealedCfg)
	_, _ = io.WriteString(conn, "OK SEALED\n")
}

func (s *Server) handleDial(clientConn net.Conn, rawTarget string) {
	ap, err := ParseAndValidateDialTarget(rawTarget)
	if err != nil {
		_, _ = fmt.Fprintf(clientConn, "ERR %s\n", err.Error())
		_ = clientConn.Close()
		return
	}

	dialFn := s.cfg.DialTarget
	if dialFn == nil {
		dialFn = func(target netip.AddrPort, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("tcp4", target.String(), timeout)
		}
	}
	targetConn, err := dialFn(ap, s.cfg.DialTimeout)
	if err != nil {
		_, _ = fmt.Fprintf(clientConn, "ERR dial failed: %v\n", err)
		_ = clientConn.Close()
		return
	}

	if _, err := io.WriteString(clientConn, "OK\n"); err != nil {
		_ = targetConn.Close()
		_ = clientConn.Close()
		return
	}
	pipeBidirectional(clientConn, targetConn)
}

func (s *Server) handleListen(ctrlConn net.Conn, rawPort string) {
	port64, err := strconv.ParseUint(strings.TrimSpace(rawPort), 10, 16)
	if err != nil {
		_, _ = io.WriteString(ctrlConn, "ERR invalid port\n")
		_ = ctrlConn.Close()
		return
	}
	port := uint16(port64)
	if err := ValidatePackerListenPort(port, s.cfg.PackerPortMin, s.cfg.PackerPortMax); err != nil {
		_, _ = fmt.Fprintf(ctrlConn, "ERR %s\n", err.Error())
		_ = ctrlConn.Close()
		return
	}

	bindAddr := net.JoinHostPort(s.cfg.NATBindIP, strconv.Itoa(int(port)))
	s.revMu.Lock()
	if _, busy := s.revPorts[port]; busy {
		s.revMu.Unlock()
		_, _ = fmt.Fprintf(ctrlConn, "ERR port %d already bound\n", port)
		_ = ctrlConn.Close()
		return
	}
	ln, err := net.Listen("tcp4", bindAddr)
	if err != nil {
		s.revMu.Unlock()
		_, _ = fmt.Fprintf(ctrlConn, "ERR bind %s failed: %v\n", bindAddr, err)
		_ = ctrlConn.Close()
		return
	}
	sess := &reversePortSession{
		port:    port,
		ln:      ln,
		pending: make(map[uint64]pendingReverseConn),
	}
	s.revPorts[port] = sess
	s.revMu.Unlock()

	cleanup := func() {
		_ = ln.Close()
		s.revMu.Lock()
		delete(s.revPorts, port)
		s.revMu.Unlock()
		sess.mu.Lock()
		for _, p := range sess.pending {
			_ = p.conn.Close()
		}
		sess.pending = nil
		sess.mu.Unlock()
		_ = ctrlConn.Close()
	}

	if _, err := fmt.Fprintf(ctrlConn, "OK %d\n", port); err != nil {
		cleanup()
		return
	}

	// Watch control stream EOF so closing the Packer session tears down the listener immediately.
	go func() {
		var buf [16]byte
		for {
			if _, err := ctrlConn.Read(buf[:]); err != nil {
				cleanup()
				return
			}
		}
	}()

	var writeMu sync.Mutex
	for {
		vmConn, err := ln.Accept()
		if err != nil {
			cleanup()
			return
		}
		connID := s.nextConnID.Add(1)
		sess.mu.Lock()
		// Evict any expired unclaimed connections before adding a new one.
		now := time.Now()
		for k, p := range sess.pending {
			if now.After(p.expiresAt) {
				_ = p.conn.Close()
				delete(sess.pending, k)
			}
		}
		if sess.pending == nil {
			sess.mu.Unlock()
			_ = vmConn.Close()
			return
		}
		sess.pending[connID] = pendingReverseConn{
			conn:      vmConn,
			expiresAt: now.Add(10 * time.Second),
		}
		sess.mu.Unlock()

		writeMu.Lock()
		_, wErr := fmt.Fprintf(ctrlConn, "ACCEPT %d\n", connID)
		writeMu.Unlock()
		if wErr != nil {
			cleanup()
			return
		}
	}
}

func (s *Server) handleAcceptJoin(joinConn net.Conn, rawPort string, rawConnID string) {
	port64, err1 := strconv.ParseUint(strings.TrimSpace(rawPort), 10, 16)
	connID, err2 := strconv.ParseUint(strings.TrimSpace(rawConnID), 10, 64)
	if err1 != nil || err2 != nil {
		_, _ = io.WriteString(joinConn, "ERR invalid ACCEPT_JOIN args\n")
		_ = joinConn.Close()
		return
	}
	port := uint16(port64)

	s.revMu.Lock()
	sess := s.revPorts[port]
	s.revMu.Unlock()
	if sess == nil {
		_, _ = io.WriteString(joinConn, "ERR reverse port not active\n")
		_ = joinConn.Close()
		return
	}

	sess.mu.Lock()
	entry, ok := sess.pending[connID]
	if ok {
		delete(sess.pending, connID)
	}
	sess.mu.Unlock()
	if !ok {
		_, _ = io.WriteString(joinConn, "ERR unknown or expired conn_id\n")
		_ = joinConn.Close()
		return
	}

	if _, err := io.WriteString(joinConn, "OK\n"); err != nil {
		_ = entry.conn.Close()
		_ = joinConn.Close()
		return
	}
	pipeBidirectional(joinConn, entry.conn)
}

func absInt64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}
