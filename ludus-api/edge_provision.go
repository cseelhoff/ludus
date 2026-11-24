package ludusapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"ludusapi/edgeproxy"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	activeEdgeMu     sync.Mutex
	activeEdgeClient *edgeproxy.Client

	packerPortMu   sync.Mutex
	packerPortsUse uint64 // Bitset for up to 64 ports anchored at PackerPortMin (default 8350..8399)
)

// ActiveEdgeProxyClient returns the initialized in-process edgeproxy.Client when edge_proxy_enabled is active.
func ActiveEdgeProxyClient() *edgeproxy.Client {
	activeEdgeMu.Lock()
	defer activeEdgeMu.Unlock()
	return activeEdgeClient
}

// ResetActiveEdgeProxyClient closes and clears any active edgeproxy.Client (used on shutdown and in tests).
func ResetActiveEdgeProxyClient() {
	activeEdgeMu.Lock()
	c := activeEdgeClient
	activeEdgeClient = nil
	activeEdgeMu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

// EnsureActiveEdgeProxyClient initializes the mTLS edgeproxy.Client and starts its local
// dual-protocol (SOCKS5 + HTTP CONNECT + HTTP forward) loopback listener when EdgeProxyEnabled is true.
func EnsureActiveEdgeProxyClient(cfg *Configuration) (*edgeproxy.Client, error) {
	if cfg == nil {
		cfg = &ServerConfiguration
	}
	cfg.ApplyRemoteProxmoxDefaults()
	if !cfg.EdgeProxyEnabled {
		return nil, nil
	}

	activeEdgeMu.Lock()
	defer activeEdgeMu.Unlock()
	if activeEdgeClient != nil {
		return activeEdgeClient, nil
	}

	localBind := strings.TrimSpace(os.Getenv("LUDUS_EDGE_LOCAL_PROXY_BIND"))
	if localBind == "" {
		localBind = "127.0.0.1:1080"
	}

	client, err := edgeproxy.NewClient(edgeproxy.ClientConfig{
		EdgeAddr:       cfg.EdgeProxyAddr,
		CAFile:         cfg.EdgeProxyCAFile,
		CertFile:       cfg.EdgeProxyCertFile,
		KeyFile:        cfg.EdgeProxyKeyFile,
		LocalProxyBind: localBind,
	})
	if err != nil {
		return nil, fmt.Errorf("initializing edgeproxy client for %s: %w", cfg.EdgeProxyAddr, err)
	}
	if err := client.StartLocalLoopbackProxy(); err != nil {
		return nil, err
	}
	activeEdgeClient = client
	return client, nil
}

// AcquirePackerReversePort reserves a dedicated port in [PackerHTTPPortMin..PackerHTTPPortMax]
// using a 64-slot bitset so parallel Packer builds never collide on ludusnat.
func AcquirePackerReversePort() (uint16, error) {
	minPort := ServerConfiguration.PackerHTTPPortMin
	maxPort := ServerConfiguration.PackerHTTPPortMax
	if minPort <= 0 {
		minPort = edgeproxy.DefaultPackerPortMin
	}
	if maxPort <= 0 {
		maxPort = edgeproxy.DefaultPackerPortMax
	}
	span := maxPort - minPort + 1
	if span <= 0 {
		return 0, fmt.Errorf("invalid Packer HTTP port range [%d..%d]", minPort, maxPort)
	}
	if span > 64 {
		span = 64
	}

	packerPortMu.Lock()
	defer packerPortMu.Unlock()
	for i := 0; i < span; i++ {
		mask := uint64(1) << uint(i)
		if packerPortsUse&mask == 0 {
			packerPortsUse |= mask
			return uint16(minPort + i), nil
		}
	}
	return 0, fmt.Errorf("all %d Packer reverse HTTP ports [%d..%d] are currently in use", span, minPort, minPort+span-1)
}

// ReleasePackerReversePort releases a previously reserved Packer reverse HTTP port.
func ReleasePackerReversePort(port uint16) {
	minPort := ServerConfiguration.PackerHTTPPortMin
	if minPort <= 0 {
		minPort = edgeproxy.DefaultPackerPortMin
	}
	offset := int(port) - minPort
	if offset < 0 || offset >= 64 {
		return
	}
	packerPortMu.Lock()
	packerPortsUse &^= uint64(1) << uint(offset)
	packerPortMu.Unlock()
}

// BuildEdgeProxyEnvVars returns the SSH ProxyCommand and HTTP/HTTPS/NO_PROXY environment variables
// needed for Ansible (SSH + pywinrm) and Packer (SSH + WinRM + Ansible provisioner) when EdgeProxyEnabled is true.
func BuildEdgeProxyEnvVars() map[string]string {
	if !ServerConfiguration.EdgeProxyEnabled {
		return nil
	}

	localProxyAddr := "127.0.0.1:1080"
	if c := ActiveEdgeProxyClient(); c != nil && c.LocalProxyAddr() != "" {
		localProxyAddr = c.LocalProxyAddr()
	}
	proxyURL := "http://" + localProxyAddr

	execPath, err := os.Executable()
	if err != nil || strings.TrimSpace(execPath) == "" {
		execPath = "/opt/ludus/ludus-server"
	}

	noProxyItems := []string{"127.0.0.1", "localhost", "::1"}
	addHost := func(h string) {
		h = strings.TrimSpace(h)
		if h == "" {
			return
		}
		if hostOnly, _, splitErr := net.SplitHostPort(h); splitErr == nil && hostOnly != "" {
			h = hostOnly
		}
		for _, existing := range noProxyItems {
			if strings.EqualFold(existing, h) {
				return
			}
		}
		noProxyItems = append(noProxyItems, h)
	}
	if parsed, err := url.Parse(ServerConfiguration.ProxmoxURL); err == nil {
		addHost(parsed.Hostname())
	}
	addHost(ServerConfiguration.ProxmoxPublicIP)
	addHost(ServerConfiguration.ProxmoxHostname)
	addHost(ServerConfiguration.EdgeVMIP)
	noProxy := strings.Join(noProxyItems, ",")

	sshArgs := fmt.Sprintf("-C -o ControlMaster=auto -o ControlPersist=60s -o ProxyCommand=\"%s --proxy-dial %%h %%p\"", execPath)

	return map[string]string{
		"ANSIBLE_SSH_ARGS":           sshArgs,
		"HTTP_PROXY":                 proxyURL,
		"HTTPS_PROXY":                proxyURL,
		"NO_PROXY":                   noProxy,
		"http_proxy":                 proxyURL,
		"https_proxy":                proxyURL,
		"no_proxy":                   noProxy,
		"LUDUS_EDGE_PROXY_ADDR":      ServerConfiguration.EdgeProxyAddr,
		"LUDUS_EDGE_PROXY_CA_FILE":   ServerConfiguration.EdgeProxyCAFile,
		"LUDUS_EDGE_PROXY_CERT_FILE": ServerConfiguration.EdgeProxyCertFile,
		"LUDUS_EDGE_PROXY_KEY_FILE":  ServerConfiguration.EdgeProxyKeyFile,
	}
}

// ReconcileEdgeVMAndProxy performs Day-0 automatic reconciliation of the stateless ludus-edge VM
// on Proxmox (:8006) via PVEAPIToken and completes the zero-private-key first-boot mTLS + WireGuard seal.
func ReconcileEdgeVMAndProxy(ctx context.Context, cfg *Configuration) error {
	if cfg == nil {
		cfg = &ServerConfiguration
	}
	cfg.ApplyRemoteProxmoxDefaults()
	if !cfg.EdgeAutoProvision {
		return nil
	}
	if strings.TrimSpace(cfg.EdgeVMIP) == "" {
		return fmt.Errorf("edge_auto_provision is enabled, but edge_vm_ip is not set")
	}

	pki, err := EnsureControlPlanePKIForConfig(cfg)
	if err != nil {
		return err
	}

	// Fast-path: if wg_pool.json already exists AND ludus-edge responds to mTLS PING, skip Proxmox reconciliation.
	if FileExists(cfg.WireguardPoolFile) {
		pingClient, cErr := edgeproxy.NewClient(edgeproxy.ClientConfig{
			EdgeAddr:    cfg.EdgeProxyAddr,
			CAFile:      cfg.EdgeProxyCAFile,
			CertFile:    cfg.EdgeProxyCertFile,
			KeyFile:     cfg.EdgeProxyKeyFile,
			DialTimeout: 3 * time.Second,
		})
		if cErr == nil {
			pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			pErr := pingClient.Ping(pingCtx)
			cancel()
			if pErr == nil {
				return nil
			}
		}
	}

	pveClient, err := NewProxmoxBestEffortAdminClient(ctx, cfg)
	if err != nil {
		return fmt.Errorf("connecting to Proxmox for ludus-edge reconciliation: %w", err)
	}

	isoVolID, err := ensureEdgeISOOnProxmox(ctx, pveClient, cfg)
	if err != nil {
		return err
	}

	if err := ensureEdgeVMRunningOnProxmox(ctx, pveClient, cfg, isoVolID, pki.EnrollPublicB64); err != nil {
		return err
	}

	// Prepare or reload the deterministic WireGuard client pool seed and 249 public peer entries.
	seedBytes, peers, err := prepareWireGuardSeedAndPublicPeers(cfg.WireguardPoolFile, WireGuardDefaultMaxSlot)
	if err != nil {
		return err
	}

	wgPort := cfg.WireguardPort
	if wgPort <= 0 {
		wgPort = DefaultWireGuardListenPort
	}
	wgEndpoint := net.JoinHostPort(strings.TrimSpace(cfg.EdgeVMIP), strconv.Itoa(wgPort))

	// Wait for ludus-edge:8444 to become reachable and either pass mTLS Ping (already sealed on disk)
	// or complete first-boot SealEdgeNode.
	deadline := time.Now().Add(edgeReadinessWaitTimeout())
	var lastErr error
	for {
		// Check if already sealed (e.g. VM was stopped and restarted with intact scsi0 disk).
		if FileExists(cfg.WireguardPoolFile) {
			if mClient, mErr := edgeproxy.NewClient(edgeproxy.ClientConfig{
				EdgeAddr:    cfg.EdgeProxyAddr,
				CAFile:      cfg.EdgeProxyCAFile,
				CertFile:    cfg.EdgeProxyCertFile,
				KeyFile:     cfg.EdgeProxyKeyFile,
				DialTimeout: 3 * time.Second,
			}); mErr == nil {
				pCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
				pErr := mClient.Ping(pCtx)
				cancel()
				if pErr == nil {
					return nil
				}
			}
		}

		sealCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		wgServerPub, sealErr := edgeproxy.SealEdgeNode(sealCtx, cfg.EdgeProxyAddr, cfg.EdgeVMIP, pki, wgPort, peers)
		cancel()
		if sealErr == nil {
			pool := &EdgeWireGuardBundle{
				ClientPool: WireGuardClientPool{
					Version:         1,
					ServerPublicKey: wgServerPub,
					Endpoint:        wgEndpoint,
					ListenPort:      wgPort,
					ClientPoolSeed:  base64.StdEncoding.EncodeToString(seedBytes),
					MinSlot:         WireGuardMinClientSlot,
					MaxSlot:         WireGuardDefaultMaxSlot,
				},
			}
			if err := WriteWireGuardBundleFiles("", cfg.WireguardPoolFile, pool); err != nil {
				return fmt.Errorf("persisting wg_pool.json after sealing ludus-edge: %w", err)
			}
			// Verify sealed mTLS 1.3 handshake immediately.
			verifyClient, err := edgeproxy.NewClient(edgeproxy.ClientConfig{
				EdgeAddr:    cfg.EdgeProxyAddr,
				CAFile:      cfg.EdgeProxyCAFile,
				CertFile:    cfg.EdgeProxyCertFile,
				KeyFile:     cfg.EdgeProxyKeyFile,
				DialTimeout: 5 * time.Second,
			})
			if err != nil {
				return err
			}
			vCtx, vCancel := context.WithTimeout(ctx, 5*time.Second)
			defer vCancel()
			if err := verifyClient.Ping(vCtx); err != nil {
				return fmt.Errorf("verifying sealed mTLS PING to ludus-edge (%s): %w", cfg.EdgeProxyAddr, err)
			}
			return nil
		}

		lastErr = sealErr
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting to seal/verify ludus-edge at %s: %w", cfg.EdgeProxyAddr, lastErr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func edgeReadinessWaitTimeout() time.Duration {
	if raw := strings.TrimSpace(os.Getenv("LUDUS_EDGE_WAIT_TIMEOUT")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d > 0 {
			return d
		}
	}
	return 60 * time.Second
}

// EnsureControlPlanePKIForConfig ensures mTLS CA + client leaf + enrollment keypair exist in cfg.EdgeStateDir.
func EnsureControlPlanePKIForConfig(cfg *Configuration) (*edgeproxy.ControlPlanePKI, error) {
	stateDir := strings.TrimSpace(cfg.EdgeStateDir)
	if stateDir == "" {
		stateDir = filepath.Join(ludusInstallPath, "db", "edge")
	}
	return edgeproxy.EnsureControlPlanePKI(stateDir)
}

func prepareWireGuardSeedAndPublicPeers(poolPath string, maxSlot int) ([]byte, []edgeproxy.WireGuardPeerPublicEntry, error) {
	var seed [32]byte
	haveSeed := false
	if FileExists(poolPath) {
		if existing, err := LoadWireGuardClientPool(poolPath); err == nil {
			if decoded, dErr := base64.StdEncoding.DecodeString(strings.TrimSpace(existing.ClientPoolSeed)); dErr == nil && len(decoded) == 32 {
				copy(seed[:], decoded)
				haveSeed = true
				if existing.MaxSlot >= WireGuardMinClientSlot {
					maxSlot = existing.MaxSlot
				}
			}
		}
	}
	if !haveSeed {
		if _, err := rand.Read(seed[:]); err != nil {
			return nil, nil, err
		}
	}

	peers := make([]edgeproxy.WireGuardPeerPublicEntry, 0, maxSlot-WireGuardMinClientSlot+1)
	for slot := WireGuardMinClientSlot; slot <= maxSlot; slot++ {
		_, pub, err := DeriveWireGuardSlotKeypair(seed[:], slot)
		if err != nil {
			return nil, nil, err
		}
		peers = append(peers, edgeproxy.WireGuardPeerPublicEntry{
			Slot:      slot,
			PublicKey: pub,
		})
	}
	return seed[:], peers, nil
}

func ensureEdgeISOOnProxmox(ctx context.Context, client *ProxmoxRESTClient, cfg *Configuration) (string, error) {
	isoStorage := strings.TrimSpace(cfg.ProxmoxISOStoragePool)
	if isoStorage == "" {
		isoStorage = "local"
	}
	isoFilename := filepath.Base(strings.TrimSpace(cfg.EdgeISOPath))
	if isoFilename == "" || isoFilename == "." || isoFilename == "/" {
		isoFilename = "ludus-edge.iso"
	}
	if FileExists(cfg.EdgeISOPath) {
		if f, err := os.Open(cfg.EdgeISOPath); err == nil {
			h := sha256.New()
			if _, cErr := io.Copy(h, f); cErr == nil {
				ext := filepath.Ext(isoFilename)
				base := strings.TrimSuffix(isoFilename, ext)
				isoFilename = fmt.Sprintf("%s-%s%s", base, hex.EncodeToString(h.Sum(nil))[:10], ext)
			}
			_ = f.Close()
		}
	}
	targetVolID := fmt.Sprintf("%s:iso/%s", isoStorage, isoFilename)

	var items []struct {
		VolID string `json:"volid"`
	}
	q := url.Values{}
	q.Set("content", "iso")
	contentPath := fmt.Sprintf("/nodes/%s/storage/%s/content", url.PathEscape(cfg.ProxmoxNode), url.PathEscape(isoStorage))
	if err := client.Do(ctx, http.MethodGet, contentPath, q, &items); err != nil {
		return "", fmt.Errorf("listing ISO storage %s on node %s: %w", isoStorage, cfg.ProxmoxNode, err)
	}
	for _, it := range items {
		if it.VolID == targetVolID || strings.HasSuffix(it.VolID, "/"+isoFilename) {
			return it.VolID, nil
		}
	}

	if !FileExists(cfg.EdgeISOPath) {
		return "", fmt.Errorf("ludus-edge ISO %s not found on Proxmox (%s) and local ISO %s does not exist",
			targetVolID, isoStorage, cfg.EdgeISOPath)
	}

	upid, err := uploadISOFileREST(ctx, client, cfg.ProxmoxNode, isoStorage, isoFilename, cfg.EdgeISOPath)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(upid, "UPID:") {
		if err := waitForProxmoxTaskREST(ctx, client, cfg.ProxmoxNode, upid); err != nil {
			return "", fmt.Errorf("uploading %s to %s: %w", isoFilename, isoStorage, err)
		}
	}
	return targetVolID, nil
}

func uploadISOFileREST(ctx context.Context, client *ProxmoxRESTClient, node, storage, filename, localPath string) (string, error) {
	f, err := os.Open(localPath)
	if err != nil {
		return "", fmt.Errorf("opening %s: %w", localPath, err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", localPath, err)
	}
	fileSize := st.Size()

	// Proxmox VE's pveproxy rejects chunked Transfer-Encoding (HTTP 501) on
	// /storage/{storage}/upload. Pre-render the small multipart header/footer
	// boundaries around the raw file reader so req.ContentLength is exact with
	// zero full-ISO heap buffering.
	var prefixBuf bytes.Buffer
	mw := multipart.NewWriter(&prefixBuf)
	contentType := mw.FormDataContentType()
	if err := mw.WriteField("content", "iso"); err != nil {
		return "", err
	}
	if _, err := mw.CreateFormFile("filename", filename); err != nil {
		return "", err
	}
	var suffixBuf bytes.Buffer
	_, _ = fmt.Fprintf(&suffixBuf, "\r\n--%s--\r\n", mw.Boundary())

	bodyReader := io.MultiReader(&prefixBuf, io.LimitReader(f, fileSize), &suffixBuf)
	totalLen := int64(prefixBuf.Len()) + fileSize + int64(suffixBuf.Len())

	uploadURL := fmt.Sprintf("%s/nodes/%s/storage/%s/upload", client.BaseURL, url.PathEscape(node), url.PathEscape(storage))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL, bodyReader)
	if err != nil {
		return "", err
	}
	req.ContentLength = totalLen
	req.Header.Set("Content-Type", contentType)
	if client.APITokenID != "" && client.APISecret != "" {
		req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", client.APITokenID, client.APISecret))
	} else if client.Ticket != "" {
		req.AddCookie(&http.Cookie{Name: "PVEAuthCookie", Value: client.Ticket})
		if client.CSRFToken != "" {
			req.Header.Set("CSRFPreventionToken", client.CSRFToken)
		}
	}

	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("POST %s: %w", uploadURL, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("Proxmox ISO upload failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var env struct {
		Data string `json:"data"`
	}
	_ = json.Unmarshal(body, &env)
	return env.Data, nil
}

func ensureEdgeVMRunningOnProxmox(ctx context.Context, client *ProxmoxRESTClient, cfg *Configuration, isoVolID string, enrollPubB64 string) error {
	var vms []struct {
		VMID   int    `json:"vmid"`
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	qemuListPath := fmt.Sprintf("/nodes/%s/qemu", url.PathEscape(cfg.ProxmoxNode))
	if err := client.Do(ctx, http.MethodGet, qemuListPath, nil, &vms); err != nil {
		return fmt.Errorf("listing QEMU VMs on %s: %w", cfg.ProxmoxNode, err)
	}

	targetVMID := 0
	currentStatus := ""
	for _, vm := range vms {
		if (cfg.EdgeVMID > 0 && vm.VMID == cfg.EdgeVMID) || (vm.Name != "" && vm.Name == cfg.EdgeVMName) {
			targetVMID = vm.VMID
			currentStatus = vm.Status
			break
		}
	}

	if targetVMID == 0 {
		if cfg.EdgeVMID > 0 {
			targetVMID = cfg.EdgeVMID
		} else {
			var nextIDRaw interface{}
			if err := client.Do(ctx, http.MethodGet, "/cluster/nextid", nil, &nextIDRaw); err != nil {
				return fmt.Errorf("allocating next Proxmox VMID for %s: %w", cfg.EdgeVMName, err)
			}
			switch v := nextIDRaw.(type) {
			case string:
				targetVMID, _ = strconv.Atoi(v)
			case float64:
				targetVMID = int(v)
			}
			if targetVMID <= 0 {
				return fmt.Errorf("unexpected /cluster/nextid value %v", nextIDRaw)
			}
		}

		sshLine, err := edgeproxy.FormatEnrollSSHAuthorizedKey(enrollPubB64)
		if err != nil {
			return err
		}
		// Proxmox cloud-init sshkeys uses raw RFC 3986 percent-encoding (%20, never '+').
		encodedSSHKeys := strings.ReplaceAll(url.QueryEscape(sshLine), "+", "%20")

		vmStorage := strings.TrimSpace(cfg.ProxmoxVMStoragePool)
		if vmStorage == "" {
			vmStorage = "local-lvm"
		}
		mgmtIP := strings.TrimSpace(cfg.EdgeVMIP)
		if !strings.Contains(mgmtIP, "/") {
			prefix := cfg.EdgeVMCIDRPrefix
			if prefix <= 0 {
				prefix = 24
			}
			mgmtIP = fmt.Sprintf("%s/%d", mgmtIP, prefix)
		}
		ipconfig0 := "ip=" + mgmtIP
		if gw := strings.TrimSpace(cfg.EdgeVMGateway); gw != "" {
			ipconfig0 += ",gw=" + gw
		}
		natIP := strings.TrimSpace(cfg.EdgeNATIP)
		if !strings.Contains(natIP, "/") {
			natIP += "/24"
		}
		net1Spec := fmt.Sprintf("virtio,bridge=%s,mtu=1", cfg.EffectiveLudusNATInterface())
		if mac := strings.TrimSpace(cfg.EdgeNATMAC); mac != "" {
			net1Spec = fmt.Sprintf("virtio=%s,bridge=%s,mtu=1", strings.ToUpper(mac), cfg.EffectiveLudusNATInterface())
		}

		form := url.Values{}
		form.Set("vmid", strconv.Itoa(targetVMID))
		form.Set("name", cfg.EdgeVMName)
		form.Set("pool", "ADMIN")
		form.Set("ostype", "l26")
		form.Set("cores", "2")
		form.Set("memory", "512")
		form.Set("scsihw", "virtio-scsi-single")
		form.Set("agent", "enabled=1")
		form.Set("onboot", "1")
		form.Set("ide2", fmt.Sprintf("%s,media=cdrom", isoVolID))
		form.Set("scsi0", fmt.Sprintf("%s:1", vmStorage))
		form.Set("ide0", fmt.Sprintf("%s:cloudinit", vmStorage))
		form.Set("boot", "order=ide2")
		form.Set("net0", fmt.Sprintf("virtio,bridge=%s", cfg.EdgeVMBridge))
		form.Set("net1", net1Spec)
		form.Set("ipconfig0", ipconfig0)
		form.Set("ipconfig1", fmt.Sprintf("ip=%s", natIP))
		form.Set("ciuser", "ludus-edge")
		form.Set("sshkeys", encodedSSHKeys)

		var createUPID string
		if err := client.Do(ctx, http.MethodPost, qemuListPath, form, &createUPID); err != nil {
			return fmt.Errorf("creating %s VM (VMID %d) on %s: %w", cfg.EdgeVMName, targetVMID, cfg.ProxmoxNode, err)
		}
		if strings.HasPrefix(createUPID, "UPID:") {
			if err := waitForProxmoxTaskREST(ctx, client, cfg.ProxmoxNode, createUPID); err != nil {
				return fmt.Errorf("waiting for %s VM creation task: %w", cfg.EdgeVMName, err)
			}
		}
		currentStatus = "stopped"
	} else {
		var vmCfg struct {
			IDE2 string `json:"ide2"`
		}
		cfgPath := fmt.Sprintf("/nodes/%s/qemu/%d/config", url.PathEscape(cfg.ProxmoxNode), targetVMID)
		if err := client.Do(ctx, http.MethodGet, cfgPath, nil, &vmCfg); err == nil {
			if vmCfg.IDE2 != "" && !strings.HasPrefix(vmCfg.IDE2, isoVolID+",") && vmCfg.IDE2 != isoVolID {
				upd := url.Values{}
				upd.Set("ide2", fmt.Sprintf("%s,media=cdrom", isoVolID))
				var cfgRes interface{}
				if err := client.Do(ctx, http.MethodPost, cfgPath, upd, &cfgRes); err == nil && currentStatus == "running" {
					stopPath := fmt.Sprintf("/nodes/%s/qemu/%d/status/stop", url.PathEscape(cfg.ProxmoxNode), targetVMID)
					var stopUPID string
					if err := client.Do(ctx, http.MethodPost, stopPath, nil, &stopUPID); err == nil && strings.HasPrefix(stopUPID, "UPID:") {
						_ = waitForProxmoxTaskREST(ctx, client, cfg.ProxmoxNode, stopUPID)
					}
					currentStatus = "stopped"
				}
			}
		}
	}

	if currentStatus != "running" {
		startPath := fmt.Sprintf("/nodes/%s/qemu/%d/status/start", url.PathEscape(cfg.ProxmoxNode), targetVMID)
		var startUPID string
		if err := client.Do(ctx, http.MethodPost, startPath, nil, &startUPID); err != nil {
			return fmt.Errorf("starting %s VM (VMID %d): %w", cfg.EdgeVMName, targetVMID, err)
		}
		if strings.HasPrefix(startUPID, "UPID:") {
			if err := waitForProxmoxTaskREST(ctx, client, cfg.ProxmoxNode, startUPID); err != nil {
				return fmt.Errorf("waiting for %s VM start task: %w", cfg.EdgeVMName, err)
			}
		}
	}

	return nil
}

func waitForProxmoxTaskREST(ctx context.Context, client *ProxmoxRESTClient, node string, upid string) error {
	statusPath := fmt.Sprintf("/nodes/%s/tasks/%s/status", url.PathEscape(node), url.PathEscape(upid))
	deadline := time.Now().Add(2 * time.Minute)
	for {
		var st struct {
			Status     string `json:"status"`
			ExitStatus string `json:"exitstatus"`
		}
		if err := client.Do(ctx, http.MethodGet, statusPath, nil, &st); err != nil {
			return err
		}
		if st.Status == "stopped" {
			if st.ExitStatus == "" || st.ExitStatus == "OK" {
				return nil
			}
			return fmt.Errorf("Proxmox task %s failed with exitstatus=%q", upid, st.ExitStatus)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for Proxmox task %s", upid)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
}

// FormatShellEnvExports renders environment variables as sorted POSIX KEY='VALUE' prefixes for shell invocations.
func FormatShellEnvExports(vars map[string]string) string {
	if len(vars) == 0 {
		return ""
	}
	var buf bytes.Buffer
	for k, v := range vars {
		escaped := strings.ReplaceAll(v, "'", "'\"'\"'")
		fmt.Fprintf(&buf, "%s='%s' ", k, escaped)
	}
	return buf.String()
}
