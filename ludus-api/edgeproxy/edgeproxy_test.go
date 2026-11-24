package edgeproxy

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAllowlistCIDRBoundaries(t *testing.T) {
	allowed := []string{
		"192.0.2.1:22",
		"192.0.2.102:22",
		"192.0.2.250:5986",
		"10.1.0.1:22",
		"10.2.10.11:5985",
		"10.2.20.50:3389",
		"10.254.99.254:445",
	}
	for _, target := range allowed {
		if _, err := ParseAndValidateDialTarget(target); err != nil {
			t.Fatalf("expected %s to be ALLOWED, got error: %v", target, err)
		}
	}

	denied := []string{
		"192.0.2.254:22",     // ludus-edge own ludusnat IP
		"192.0.2.254:8444",   // ludus-edge proxy port via ludusnat
		"10.0.20.180:8006",   // Proxmox management LAN (inside 10.0.0.0/16)
		"10.0.20.181:22",     // ludus-edge management IP
		"10.0.0.1:80",        // 10.0.0.0/16 supernet
		"10.255.0.1:22",      // 10.255.0.0/16 excluded
		"127.0.0.1:8081",     // loopback
		"169.254.169.254:80", // link-local metadata
		"172.16.0.1:22",      // RFC1918 172.16/12
		"192.168.1.1:443",    // RFC1918 192.168/16
		"[::1]:22",           // IPv6 loopback
		"pve-prod-02:8006",   // hostname (must reject to prevent DNS rebinding)
		"10.2.10.11:0",       // port 0
	}
	for _, target := range denied {
		if _, err := ParseAndValidateDialTarget(target); err == nil {
			t.Fatalf("SECURITY VIOLATION: expected %s to be DENIED", target)
		}
	}
}

func TestOpenSSHCloudInitEnrollmentKeyRoundTrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	sshLine, err := FormatEnrollSSHAuthorizedKey(pubB64)
	if err != nil {
		t.Fatalf("FormatEnrollSSHAuthorizedKey: %v", err)
	}
	if !strings.HasPrefix(sshLine, "ssh-ed25519 ") || !strings.HasSuffix(sshLine, " ludus-edge-enroll") {
		t.Fatalf("unexpected OpenSSH line format: %q", sshLine)
	}

	authorizedKeysFile := "# Cloud-init generated\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJ1bmsxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTA= unrelated-key\n" + sshLine + "\n"
	parsedB64, err := ParseEnrollSSHAuthorizedKey(authorizedKeysFile)
	if err != nil {
		t.Fatalf("ParseEnrollSSHAuthorizedKey: %v", err)
	}
	if parsedB64 != pubB64 {
		t.Fatalf("round-trip mismatch: got %q, want %q", parsedB64, pubB64)
	}
}

func TestEndToEndEnrollmentMTLSDialProxyAndReversePackerHTTP(t *testing.T) {
	ctrlDir := t.TempDir()
	edgeStateDir := t.TempDir()

	pki, err := EnsureControlPlanePKI(ctrlDir)
	if err != nil {
		t.Fatalf("EnsureControlPlanePKI: %v", err)
	}

	plainUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "winrm-5985-ok:"+r.URL.Path)
	}))
	defer plainUpstream.Close()

	tlsUpstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "winrm-5986-ok:"+r.URL.Path)
	}))
	defer tlsUpstream.Close()

	var edgeDialCount atomic.Int32
	srv, err := NewServer(ServerConfig{
		ListenAddr:        "127.0.0.1:0",
		StateDir:          edgeStateDir,
		EnrollPublicB64:   pki.EnrollPublicB64,
		NATBindIP:         "127.0.0.1",
		PackerPortMin:     18350,
		PackerPortMax:     18360,
		EnableWGQuickHook: false,
		DialTarget: func(ap netip.AddrPort, timeout time.Duration) (net.Conn, error) {
			edgeDialCount.Add(1)
			switch ap.String() {
			case "10.2.10.11:5985", "192.0.2.102:22":
				return net.DialTimeout("tcp", plainUpstream.Listener.Addr().String(), timeout)
			case "10.2.10.11:5986":
				return net.DialTimeout("tcp", tlsUpstream.Listener.Addr().String(), timeout)
			default:
				return nil, fmt.Errorf("unexpected simulated range target %s", ap.String())
			}
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("srv.Start: %v", err)
	}
	defer srv.Close()

	if srv.IsSealed() {
		t.Fatalf("expected fresh server to start unsealed")
	}

	// 1. Tampered enrollment key must be rejected!
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	wrongPKI := *pki
	wrongPKI.EnrollPrivB64 = base64.StdEncoding.EncodeToString(wrongPriv)
	if _, err := SealEdgeNode(context.Background(), srv.Addr(), "127.0.0.1", &wrongPKI, 51820, nil); err == nil {
		t.Fatalf("SECURITY VIOLATION: SealEdgeNode succeeded with wrong enrollment private key")
	}

	// 2. Legitimate zero-private-key SealEdgeNode succeeds and transitions listener to strict mTLS 1.3.
	peers := []WireGuardPeerPublicEntry{
		{Slot: 2, PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
		{Slot: 3, PublicKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="},
	}
	wgServerPub, err := SealEdgeNode(context.Background(), srv.Addr(), "127.0.0.1", pki, 51820, peers)
	if err != nil {
		t.Fatalf("SealEdgeNode failed: %v", err)
	}
	if wgServerPub == "" || !srv.IsSealed() {
		t.Fatalf("expected non-empty wgServerPub and sealed server state")
	}

	wgConfBytes, err := os.ReadFile(filepath.Join(edgeStateDir, "wg0.conf"))
	if err != nil {
		t.Fatalf("reading sealed wg0.conf: %v", err)
	}
	if !strings.Contains(string(wgConfBytes), "AllowedIPs = 198.51.100.2/32") {
		t.Fatalf("sealed wg0.conf missing peer slot 2")
	}

	// 3. Re-sealing an already-sealed node must fail (mTLS client cert required + enrollment disabled).
	if _, err := SealEdgeNode(context.Background(), srv.Addr(), "127.0.0.1", pki, 51820, peers); err == nil {
		t.Fatalf("SECURITY VIOLATION: re-sealing an already sealed edge node succeeded")
	}

	// 4. Unauthenticated TLS 1.3 client without ludus client.crt must fail handshake/read.
	unauthConn, err := tls.Dial("tcp", srv.Addr(), &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	})
	if err == nil {
		_, writeErr := io.WriteString(unauthConn, "PING\n")
		buf := make([]byte, 16)
		_, readErr := unauthConn.Read(buf)
		_ = unauthConn.Close()
		if writeErr == nil && readErr == nil {
			t.Fatalf("SECURITY VIOLATION: unauthenticated TLS client completed PING without client certificate")
		}
	}

	// 5. Authenticated mTLS 1.3 Client: Ping + SSRF rejection + local dual-protocol loopback proxy + Reverse Packer HTTP.
	client, err := NewClient(ClientConfig{
		EdgeAddr:       srv.Addr(),
		CAFile:         filepath.Join(ctrlDir, "ca.crt"),
		CertFile:       filepath.Join(ctrlDir, "client.crt"),
		KeyFile:        filepath.Join(ctrlDir, "client.key"),
		LocalProxyBind: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	if err := client.Ping(context.Background()); err != nil {
		t.Fatalf("mTLS Ping failed: %v", err)
	}

	// Verify SSRF denial both client-side and server-side (even if client check bypassed on wire).
	if _, err := client.Dial(context.Background(), "10.0.20.180:8006"); err == nil {
		t.Fatalf("expected client.Dial to 10.0.20.180:8006 to be denied")
	}
	rawTLSConn, err := client.openEdgeStream(context.Background())
	if err != nil {
		t.Fatalf("openEdgeStream: %v", err)
	}
	_, _ = io.WriteString(rawTLSConn, "DIAL 10.0.20.180:8006\n")
	ssrfReply, _ := bufio.NewReader(rawTLSConn).ReadString('\n')
	_ = rawTLSConn.Close()
	if !strings.HasPrefix(strings.TrimSpace(ssrfReply), "ERR ") {
		t.Fatalf("SECURITY VIOLATION: server did not reject DIAL 10.0.20.180:8006, got %q", ssrfReply)
	}

	if err := client.StartLocalLoopbackProxy(); err != nil {
		t.Fatalf("StartLocalLoopbackProxy: %v", err)
	}
	proxyURL, _ := url.Parse("http://" + client.LocalProxyAddr())

	proxiedHTTPClient := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}
	respPlain, err := proxiedHTTPClient.Post("http://10.2.10.11:5985/wsman", "application/soap+xml", strings.NewReader("<soap/>"))
	if err != nil {
		t.Fatalf("plain HTTP proxy request failed: %v", err)
	}
	bodyPlain, _ := io.ReadAll(respPlain.Body)
	_ = respPlain.Body.Close()
	if string(bodyPlain) != "winrm-5985-ok:/wsman" {
		t.Fatalf("unexpected plain HTTP proxy body: %q", string(bodyPlain))
	}

	respTLS, err := proxiedHTTPClient.Post("https://10.2.10.11:5986/wsman", "application/soap+xml", strings.NewReader("<soap/>"))
	if err != nil {
		t.Fatalf("HTTPS CONNECT proxy request failed: %v", err)
	}
	bodyTLS, _ := io.ReadAll(respTLS.Body)
	_ = respTLS.Body.Close()
	if string(bodyTLS) != "winrm-5986-ok:/wsman" {
		t.Fatalf("unexpected HTTPS CONNECT proxy body: %q", string(bodyTLS))
	}

	// Test SOCKS5 CONNECT to range router WAN IP 192.0.2.102:22 on the exact same local loopback port!
	socksConn, err := net.DialTimeout("tcp", client.LocalProxyAddr(), 3*time.Second)
	if err != nil {
		t.Fatalf("dialing SOCKS5 proxy: %v", err)
	}
	_, _ = socksConn.Write([]byte{0x05, 0x01, 0x00})
	greet := make([]byte, 2)
	if _, err := io.ReadFull(socksConn, greet); err != nil || greet[0] != 0x05 || greet[1] != 0x00 {
		t.Fatalf("SOCKS5 greeting failed: %v %v", err, greet)
	}
	req := []byte{0x05, 0x01, 0x00, 0x01, 192, 0, 2, 102, 0x00, 22}
	_, _ = socksConn.Write(req)
	rep := make([]byte, 10)
	if _, err := io.ReadFull(socksConn, rep); err != nil || rep[1] != 0x00 {
		t.Fatalf("SOCKS5 CONNECT failed: %v %v", err, rep)
	}
	_, _ = fmt.Fprintf(socksConn, "GET /socks-check HTTP/1.1\r\nHost: 192.0.2.102:22\r\nConnection: close\r\n\r\n")
	socksHTTPResp, err := io.ReadAll(socksConn)
	_ = socksConn.Close()
	if err != nil || !strings.Contains(string(socksHTTPResp), "winrm-5985-ok:/socks-check") {
		t.Fatalf("SOCKS5 proxied HTTP failed: err=%v body=%q", err, string(socksHTTPResp))
	}
	if gotDials := edgeDialCount.Load(); gotDials != 3 {
		t.Fatalf("expected all 3 range connections (5985, 5986, SOCKS5 192.0.2.102:22) to traverse ludus-edge mTLS DIAL, got %d", gotDials)
	}

	// 6. Test Reverse Packer HTTP preseed listener (LISTEN 18352 -> local Packer HTTP server).
	packerLocalSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "d-i mirror/country string manual # path=%s", r.URL.Path)
	}))
	defer packerLocalSrv.Close()
	packerLocalAddr := packerLocalSrv.Listener.Addr().String()

	// Port outside [18350..18360] must be rejected.
	if _, err := client.OpenPackerReverseListener(context.Background(), 9999, packerLocalAddr); err == nil {
		t.Fatalf("expected port 9999 outside Packer range to be rejected")
	}

	rev, err := client.OpenPackerReverseListener(context.Background(), 18352, packerLocalAddr)
	if err != nil {
		t.Fatalf("OpenPackerReverseListener(18352) failed: %v", err)
	}

	for i := 0; i < 3; i++ {
		preseedResp, err := http.Get(fmt.Sprintf("http://127.0.0.1:18352/debian-12-preseed-%d.cfg", i))
		if err != nil {
			t.Fatalf("reverse preseed GET #%d failed: %v", i, err)
		}
		preseedBody, _ := io.ReadAll(preseedResp.Body)
		_ = preseedResp.Body.Close()
		want := fmt.Sprintf("d-i mirror/country string manual # path=/debian-12-preseed-%d.cfg", i)
		if string(preseedBody) != want {
			t.Fatalf("reverse preseed GET #%d mismatch: got %q, want %q", i, string(preseedBody), want)
		}
	}

	// Closing ReverseTunnel must immediately release port 18352 on ludus-edge.
	_ = rev.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, dialErr := net.DialTimeout("tcp", "127.0.0.1:18352", 100*time.Millisecond)
		if dialErr != nil {
			break
		}
		_ = c.Close()
		time.Sleep(30 * time.Millisecond)
	}
	rev2, err := client.OpenPackerReverseListener(context.Background(), 18352, packerLocalAddr)
	if err != nil {
		t.Fatalf("expected port 18352 to be re-bindable after Close(): %v", err)
	}
	_ = rev2.Close()
}
