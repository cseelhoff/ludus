package edgeproxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ClientConfig configures the Ludus-side edge proxy client and local loopback forwarder.
type ClientConfig struct {
	EdgeAddr       string // e.g. "10.0.20.181:8444"
	CAFile         string
	CertFile       string
	KeyFile        string
	ServerName     string // default "ludus-edge"
	LocalProxyBind string // default "127.0.0.1:1080"
	DialTimeout    time.Duration
}

// Client dials range targets and binds reverse Packer HTTP listeners via ludus-edge:8444 over mTLS 1.3,
// and optionally exposes a dual-protocol (SOCKS5 + HTTP CONNECT / HTTP forward) listener on 127.0.0.1:1080.
type Client struct {
	cfg       ClientConfig
	tlsConfig *tls.Config

	mu          sync.Mutex
	localLn     net.Listener
	httpForward *http.Transport
}

// NewClient constructs a mTLS 1.3 edgeproxy Client.
func NewClient(cfg ClientConfig) (*Client, error) {
	if strings.TrimSpace(cfg.EdgeAddr) == "" {
		return nil, fmt.Errorf("EdgeAddr is required")
	}
	if strings.TrimSpace(cfg.LocalProxyBind) == "" {
		cfg.LocalProxyBind = "127.0.0.1:1080"
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 15 * time.Second
	}
	tlsCfg, err := BuildClientTLSConfig(cfg.CAFile, cfg.CertFile, cfg.KeyFile, cfg.ServerName)
	if err != nil {
		return nil, err
	}
	c := &Client{
		cfg:       cfg,
		tlsConfig: tlsCfg,
	}
	c.httpForward = &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return c.DialRangeOrDirect(ctx, addr)
		},
		MaxIdleConns:          32,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return c, nil
}

func (c *Client) openEdgeStream(ctx context.Context) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: c.cfg.DialTimeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", c.cfg.EdgeAddr)
	if err != nil {
		return nil, fmt.Errorf("connecting to ludus-edge %s: %w", c.cfg.EdgeAddr, err)
	}
	tlsConn := tls.Client(rawConn, c.tlsConfig.Clone())
	if deadline, ok := ctx.Deadline(); ok {
		_ = tlsConn.SetDeadline(deadline)
	} else {
		_ = tlsConn.SetDeadline(time.Now().Add(c.cfg.DialTimeout))
	}
	if err := tlsConn.Handshake(); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("mTLS handshake with ludus-edge %s: %w", c.cfg.EdgeAddr, err)
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

// Ping verifies mTLS connectivity and readiness of ludus-edge:8444.
func (c *Client) Ping(ctx context.Context) error {
	conn, err := c.openEdgeStream(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "PING\n"); err != nil {
		return err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(strings.TrimSpace(line), "OK") {
		return fmt.Errorf("unexpected PING response from ludus-edge: %s", strings.TrimSpace(line))
	}
	return nil
}

// Dial tunnels a TCP connection to a Ludus range IP:port through ludus-edge:8444 over mTLS 1.3.
func (c *Client) Dial(ctx context.Context, targetAddr string) (net.Conn, error) {
	ap, err := ParseAndValidateDialTarget(targetAddr)
	if err != nil {
		return nil, err
	}
	conn, err := c.openEdgeStream(ctx)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(c.cfg.DialTimeout))
	if _, err := fmt.Fprintf(conn, "DIAL %s\n", ap.String()); err != nil {
		_ = conn.Close()
		return nil, err
	}
	br := bufio.NewReaderSize(conn, 4096)
	reply, err := br.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("reading DIAL reply for %s: %w", ap.String(), err)
	}
	reply = strings.TrimSpace(reply)
	if reply != "OK" {
		_ = conn.Close()
		return nil, fmt.Errorf("ludus-edge rejected DIAL %s: %s", ap.String(), reply)
	}
	_ = conn.SetDeadline(time.Time{})
	return &bufferedConn{Conn: conn, r: br}, nil
}

// DialRangeOrDirect routes Ludus range IPs via ludus-edge mTLS and dials non-range addresses directly.
func (c *Client) DialRangeOrDirect(ctx context.Context, addr string) (net.Conn, error) {
	if ap, err := netip.ParseAddrPort(strings.TrimSpace(addr)); err == nil && IsAllowedRangeAddr(ap.Addr()) {
		return c.Dial(ctx, ap.String())
	}
	dialer := &net.Dialer{Timeout: c.cfg.DialTimeout}
	return dialer.DialContext(ctx, "tcp", addr)
}

// ReverseTunnel represents an active LISTEN <remotePort> session forwarding ludusnat:remotePort -> 127.0.0.1:localPort.
type ReverseTunnel struct {
	RemotePort uint16
	LocalAddr  string
	ctrlConn   net.Conn
	closeOnce  sync.Once
}

// Close tears down the remote Packer preseed listener on ludus-edge immediately.
func (rt *ReverseTunnel) Close() error {
	var err error
	rt.closeOnce.Do(func() {
		if rt.ctrlConn != nil {
			err = rt.ctrlConn.Close()
		}
	})
	return err
}

// OpenPackerReverseListener asks ludus-edge to bind 192.0.2.254:<remotePort> and forwards all incoming
// HTTP preseed TCP connections to localAddr (e.g. "127.0.0.1:8352" inside the ludus container).
func (c *Client) OpenPackerReverseListener(ctx context.Context, remotePort uint16, localAddr string) (*ReverseTunnel, error) {
	conn, err := c.openEdgeStream(ctx)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(conn, "LISTEN %d\n", remotePort); err != nil {
		_ = conn.Close()
		return nil, err
	}
	br := bufio.NewReaderSize(conn, 1024)
	reply, err := br.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("reading LISTEN %d reply: %w", remotePort, err)
	}
	reply = strings.TrimSpace(reply)
	if !strings.HasPrefix(reply, "OK ") {
		_ = conn.Close()
		return nil, fmt.Errorf("ludus-edge LISTEN %d failed: %s", remotePort, reply)
	}
	_ = conn.SetDeadline(time.Time{})

	rt := &ReverseTunnel{
		RemotePort: remotePort,
		LocalAddr:  localAddr,
		ctrlConn:   conn,
	}

	go func() {
		defer rt.Close()
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) == 2 && fields[0] == "ACCEPT" {
				connID := fields[1]
				go c.joinReverseConn(remotePort, connID, localAddr)
			}
		}
	}()

	return rt, nil
}

func (c *Client) joinReverseConn(remotePort uint16, connID string, localAddr string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	edgeStream, err := c.openEdgeStream(ctx)
	if err != nil {
		return
	}
	_ = edgeStream.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(edgeStream, "ACCEPT_JOIN %d %s\n", remotePort, connID); err != nil {
		_ = edgeStream.Close()
		return
	}
	br := bufio.NewReaderSize(edgeStream, 4096)
	reply, err := br.ReadString('\n')
	if err != nil || strings.TrimSpace(reply) != "OK" {
		_ = edgeStream.Close()
		return
	}
	_ = edgeStream.SetDeadline(time.Time{})

	localConn, err := net.DialTimeout("tcp", localAddr, 5*time.Second)
	if err != nil {
		_ = edgeStream.Close()
		return
	}
	pipeBidirectional(&bufferedConn{Conn: edgeStream, r: br}, localConn)
}

// StartLocalLoopbackProxy starts the dual-protocol (SOCKS5 + HTTP CONNECT + HTTP forward) listener on LocalProxyBind.
func (c *Client) StartLocalLoopbackProxy() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.localLn != nil {
		return nil
	}
	ln, err := net.Listen("tcp", c.cfg.LocalProxyBind)
	if err != nil {
		return fmt.Errorf("binding local edge proxy listener %s: %w", c.cfg.LocalProxyBind, err)
	}
	c.localLn = ln
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go c.handleLocalProxyConn(conn)
		}
	}()
	return nil
}

// LocalProxyAddr returns the bound 127.0.0.1:<port> address of the dual-protocol proxy.
func (c *Client) LocalProxyAddr() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.localLn == nil {
		return ""
	}
	return c.localLn.Addr().String()
}

// Close shuts down the local loopback proxy listener and idle forward HTTP transports.
func (c *Client) Close() error {
	c.mu.Lock()
	ln := c.localLn
	c.localLn = nil
	c.mu.Unlock()
	if c.httpForward != nil {
		c.httpForward.CloseIdleConnections()
	}
	if ln != nil {
		return ln.Close()
	}
	return nil
}

func (c *Client) handleLocalProxyConn(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReaderSize(conn, 4096)
	firstByte, err := br.Peek(1)
	if err != nil {
		_ = conn.Close()
		return
	}
	if firstByte[0] == 0x05 {
		c.handleSOCKS5(conn, br)
		return
	}
	c.handleHTTPProxy(conn, br)
}

func (c *Client) handleSOCKS5(conn net.Conn, br *bufio.Reader) {
	// Greeting: VER(0x05), NMETHODS, METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		_ = conn.Close()
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		_ = conn.Close()
		return
	}
	// Select no-authentication (0x00).
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		_ = conn.Close()
		return
	}

	// Request: VER(0x05), CMD(0x01=CONNECT), RSV(0x00), ATYP
	reqHdr := make([]byte, 4)
	if _, err := io.ReadFull(br, reqHdr); err != nil {
		_ = conn.Close()
		return
	}
	if reqHdr[0] != 0x05 || reqHdr[1] != 0x01 {
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		_ = conn.Close()
		return
	}

	var host string
	switch reqHdr[3] {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(br, ip); err != nil {
			_ = conn.Close()
			return
		}
		host = net.IP(ip).String()
	case 0x03: // Domain
		dlen, err := br.ReadByte()
		if err != nil {
			_ = conn.Close()
			return
		}
		dom := make([]byte, int(dlen))
		if _, err := io.ReadFull(br, dom); err != nil {
			_ = conn.Close()
			return
		}
		host = string(dom)
	case 0x04: // IPv6
		ip := make([]byte, 16)
		if _, err := io.ReadFull(br, ip); err != nil {
			_ = conn.Close()
			return
		}
		host = net.IP(ip).String()
	default:
		_, _ = conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		_ = conn.Close()
		return
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(br, portBuf[:]); err != nil {
		_ = conn.Close()
		return
	}
	port := binary.BigEndian.Uint16(portBuf[:])
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))

	ctx, cancel := context.WithTimeout(context.Background(), c.cfg.DialTimeout)
	upstream, err := c.DialRangeOrDirect(ctx, target)
	cancel()
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		_ = conn.Close()
		return
	}

	_ = conn.SetDeadline(time.Time{})
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}); err != nil {
		_ = upstream.Close()
		_ = conn.Close()
		return
	}
	pipeBidirectional(&bufferedConn{Conn: conn, r: br}, upstream)
}

func (c *Client) handleHTTPProxy(conn net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		_ = conn.Close()
		return
	}

	if strings.EqualFold(req.Method, http.MethodConnect) {
		target := req.Host
		if _, _, splitErr := net.SplitHostPort(target); splitErr != nil {
			target = net.JoinHostPort(target, "443")
		}
		ctx, cancel := context.WithTimeout(context.Background(), c.cfg.DialTimeout)
		upstream, err := c.DialRangeOrDirect(ctx, target)
		cancel()
		if err != nil {
			_, _ = fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: %d\r\n\r\n%s", len(err.Error()), err.Error())
			_ = conn.Close()
			return
		}
		_ = conn.SetDeadline(time.Time{})
		if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			_ = upstream.Close()
			_ = conn.Close()
			return
		}
		pipeBidirectional(&bufferedConn{Conn: conn, r: br}, upstream)
		return
	}

	// Plain HTTP forward proxy (used by pywinrm / Packer over HTTP :5985 before WinRM HTTPS :5986 is enabled).
	defer conn.Close()
	_ = conn.SetDeadline(time.Time{})
	for {
		req.RequestURI = ""
		if req.URL.Scheme == "" {
			req.URL.Scheme = "http"
		}
		if req.URL.Host == "" {
			req.URL.Host = req.Host
		}
		req.Header.Del("Proxy-Connection")
		req.Header.Del("Proxy-Authorization")

		resp, err := c.httpForward.RoundTrip(req)
		if err != nil {
			_, _ = fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(err.Error()), err.Error())
			return
		}
		writeErr := resp.Write(conn)
		_ = resp.Body.Close()
		if writeErr != nil || req.Close || resp.Close {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		req, err = http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Time{})
	}
}

// SealEdgeNode performs the zero-private-key first-boot enrollment handshake against an unsealed ludus-edge:8444:
//  1. Requests ludus-edge's locally generated TLS CSR + WireGuard server public key (signed by EnrollPrivB64).
//  2. Signs ludus-edge's CSR with the ControlPlanePKI CA.
//  3. Sends CA cert + signed server cert + static WireGuard client public keys (2..maxSlot) signed by EnrollPrivB64.
//  4. Returns the ludus-edge WGServerPublicKey so Ludus can persist wg_pool.json.
func SealEdgeNode(ctx context.Context, edgeAddr string, edgeIP string, pki *ControlPlanePKI, wgListenPort int, peers []WireGuardPeerPublicEntry) (wgServerPubKey string, err error) {
	unsealedTLS := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // Authenticated via Ed25519 enrollment signature; zero private keys are sent.
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}

	// Step 1: ENROLL_CSR
	raw1, err := dialer.DialContext(ctx, "tcp", edgeAddr)
	if err != nil {
		return "", fmt.Errorf("dialing unsealed ludus-edge %s: %w", edgeAddr, err)
	}
	tls1 := tls.Client(raw1, unsealedTLS)
	_ = tls1.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tls1.Handshake(); err != nil {
		_ = raw1.Close()
		return "", fmt.Errorf("TLS handshake for ENROLL_CSR: %w", err)
	}

	var nonceBytes [16]byte
	_, _ = rand.Read(nonceBytes[:])
	nonce := hex.EncodeToString(nonceBytes[:])
	ts := time.Now().Unix()
	csrMsg := fmt.Sprintf("%s|%d", nonce, ts)
	csrSig, err := signEnrollMessage(pki.EnrollPrivB64, enrollDomainCSR, []byte(csrMsg))
	if err != nil {
		_ = tls1.Close()
		return "", err
	}
	csrReqBytes, _ := json.Marshal(EnrollCSRRequest{
		Nonce:     nonce,
		Timestamp: ts,
		Signature: csrSig,
	})
	if _, err := fmt.Fprintf(tls1, "ENROLL_CSR\n%s\n", string(csrReqBytes)); err != nil {
		_ = tls1.Close()
		return "", err
	}
	line1, err := bufio.NewReader(tls1).ReadString('\n')
	_ = tls1.Close()
	if err != nil {
		return "", fmt.Errorf("reading ENROLL_CSR reply: %w", err)
	}
	line1 = strings.TrimSpace(line1)
	if !strings.HasPrefix(line1, "OK ") {
		return "", fmt.Errorf("ENROLL_CSR rejected: %s", line1)
	}
	var csrResp EnrollCSRResponse
	if err := json.Unmarshal([]byte(strings.TrimPrefix(line1, "OK ")), &csrResp); err != nil {
		return "", fmt.Errorf("decoding ENROLL_CSR response: %w", err)
	}

	// Step 2: Sign ludus-edge CSR locally with ControlPlanePKI CA.
	serverCertPEM, err := pki.SignEdgeServerCSR([]byte(csrResp.EdgeCSRPEM), edgeIP)
	if err != nil {
		return "", err
	}

	// Step 3: ENROLL_SEAL (contains ONLY public certs and WireGuard peer public keys).
	sealPayload := EnrollSealPayload{
		Timestamp:     time.Now().Unix(),
		CACertPEM:     string(pki.CACertPEM),
		ServerCertPEM: string(serverCertPEM),
		WGListenPort:  wgListenPort,
		WGPeers:       peers,
	}
	payloadBytes, err := json.Marshal(sealPayload)
	if err != nil {
		return "", err
	}
	sealSig, err := signEnrollMessage(pki.EnrollPrivB64, enrollDomainSeal, payloadBytes)
	if err != nil {
		return "", err
	}
	sealReqBytes, _ := json.Marshal(EnrollSealRequest{
		PayloadJSON: string(payloadBytes),
		Signature:   sealSig,
	})

	raw2, err := dialer.DialContext(ctx, "tcp", edgeAddr)
	if err != nil {
		return "", fmt.Errorf("dialing ludus-edge for ENROLL_SEAL: %w", err)
	}
	tls2 := tls.Client(raw2, unsealedTLS)
	_ = tls2.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tls2.Handshake(); err != nil {
		_ = raw2.Close()
		return "", fmt.Errorf("TLS handshake for ENROLL_SEAL: %w", err)
	}
	if _, err := fmt.Fprintf(tls2, "ENROLL_SEAL\n%s\n", string(sealReqBytes)); err != nil {
		_ = tls2.Close()
		return "", err
	}
	line2, err := bufio.NewReader(tls2).ReadString('\n')
	_ = tls2.Close()
	if err != nil {
		return "", fmt.Errorf("reading ENROLL_SEAL reply: %w", err)
	}
	line2 = strings.TrimSpace(line2)
	if line2 != "OK SEALED" {
		return "", fmt.Errorf("ENROLL_SEAL failed: %s", line2)
	}
	return strings.TrimSpace(csrResp.WGServerPublicKey), nil
}
