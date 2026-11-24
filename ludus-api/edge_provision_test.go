package ludusapi

import (
	"context"
	"encoding/json"
	"io"
	"ludusapi/edgeproxy"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestReconcileEdgeVMAndProxyEndToEnd(t *testing.T) {
	origCfg := ServerConfiguration
	t.Cleanup(func() {
		ResetActiveEdgeProxyClient()
		ServerConfiguration = origCfg
	})

	tmpDir := t.TempDir()
	ctrlEdgeDir := filepath.Join(tmpDir, "ctrl-edge")
	edgeDiskDir := filepath.Join(tmpDir, "edge-vm-disk")
	tokenFile := filepath.Join(tmpDir, "pve-token")
	isoFile := filepath.Join(tmpDir, "ludus-edge.iso")

	if err := os.WriteFile(tokenFile, []byte("edge-svc-secret\n"), 0400); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	if err := os.WriteFile(isoFile, []byte("FAKE_ALPINE_EDGE_ISO_IMAGE_BYTES"), 0644); err != nil {
		t.Fatalf("write fake ISO: %v", err)
	}

	var (
		mu             sync.Mutex
		uploadedISOs   []string
		createdVMForm  url.Values
		vmCreateCalls  int
		vmStartCalls   int
		vmRunning      bool
		liveEdgeServer *edgeproxy.Server
		liveEdgeAddr   string
	)
	t.Cleanup(func() {
		mu.Lock()
		srv := liveEdgeServer
		mu.Unlock()
		if srv != nil {
			_ = srv.Close()
		}
	})

	// Mock Proxmox VE 9 API server handling ISO content/upload, /cluster/nextid, /nodes/<node>/qemu create & start!
	// When POST /nodes/pve-prod-02/qemu/<vmid>/status/start is called, it simulates ludus-edge booting
	// from ludus-edge.iso + cloudinit sshkeys by starting an actual unsealed edgeproxy.Server!
	pveSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gotAuth := r.Header.Get("Authorization"); gotAuth != "PVEAPIToken=ludus-svc@pve!controller=edge-svc-secret" {
			http.Error(w, "unauthorized: "+gotAuth, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		mu.Lock()
		defer mu.Unlock()

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/pve-prod-02/storage/fs-storage/content":
			items := make([]map[string]string, 0, len(uploadedISOs))
			for _, v := range uploadedISOs {
				items = append(items, map[string]string{"volid": v})
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": items})

		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/pve-prod-02/storage/fs-storage/upload":
			if r.ContentLength <= 0 || len(r.TransferEncoding) > 0 {
				http.Error(w, "chunked transfer encoding not supported", http.StatusNotImplemented)
				return
			}
			if err := r.ParseMultipartForm(4 << 20); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			f, hdr, err := r.FormFile("filename")
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			data, _ := io.ReadAll(f)
			_ = f.Close()
			if string(data) != "FAKE_ALPINE_EDGE_ISO_IMAGE_BYTES" {
				http.Error(w, "corrupted ISO upload", http.StatusBadRequest)
				return
			}
			uploadedISOs = append(uploadedISOs, "fs-storage:iso/"+hdr.Filename)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": "UPID:pve-prod-02:000001:upload:OK"})

		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api2/json/nodes/pve-prod-02/tasks/"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]string{"status": "stopped", "exitstatus": "OK"},
			})

		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/cluster/nextid":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": "181"})

		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/pve-prod-02/qemu":
			if createdVMForm == nil {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": []interface{}{}})
				return
			}
			st := "stopped"
			if vmRunning {
				st = "running"
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{
					{"vmid": 181, "name": "ludus-edge", "status": st},
				},
			})

		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/pve-prod-02/qemu":
			body, _ := io.ReadAll(r.Body)
			vals, _ := url.ParseQuery(string(body))
			createdVMForm = vals
			vmCreateCalls++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": "UPID:pve-prod-02:000002:qmcreate:OK"})

		case r.Method == http.MethodPost && r.URL.Path == "/api2/json/nodes/pve-prod-02/qemu/181/status/start":
			vmStartCalls++
			vmRunning = true
			if liveEdgeServer == nil {
				// Decode Proxmox percent-encoded sshkeys just as Proxmox cloud-init writes authorized_keys!
				rawSSHKeys, uErr := url.PathUnescape(createdVMForm.Get("sshkeys"))
				if uErr != nil {
					http.Error(w, uErr.Error(), http.StatusInternalServerError)
					return
				}
				enrollPubB64, pErr := edgeproxy.ParseEnrollSSHAuthorizedKey(rawSSHKeys)
				if pErr != nil {
					http.Error(w, pErr.Error(), http.StatusInternalServerError)
					return
				}
				srv, sErr := edgeproxy.NewServer(edgeproxy.ServerConfig{
					ListenAddr:        liveEdgeAddr,
					StateDir:          edgeDiskDir,
					EnrollPublicB64:   enrollPubB64,
					NATBindIP:         "127.0.0.1",
					EnableWGQuickHook: false,
				})
				if sErr != nil {
					http.Error(w, sErr.Error(), http.StatusInternalServerError)
					return
				}
				if err := srv.Start(); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				liveEdgeServer = srv
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": "UPID:pve-prod-02:000003:qmstart:OK"})

		default:
			http.Error(w, "unhandled path: "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer pveSrv.Close()

	// Pick a free loopback TCP port for the simulated ludus-edge VM's :8444 listener.
	probeSrv, err := edgeproxy.NewServer(edgeproxy.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		StateDir:    filepath.Join(tmpDir, "probe"),
		NATBindIP:  "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("probe server: %v", err)
	}
	_ = probeSrv.Start()
	liveEdgeAddr = probeSrv.Addr()
	_ = probeSrv.Close()

	cfg := Configuration{
		ContainerMode:         true,
		ProxmoxURL:            pveSrv.URL,
		ProxmoxNode:           "pve-prod-02",
		ProxmoxInvalidCert:    true,
		ProxmoxAuthMode:       ProxmoxAuthModeServiceToken,
		ProxmoxAPITokenID:     "ludus-svc@pve!controller",
		ProxmoxAPITokenFile:   tokenFile,
		ProxmoxISOStoragePool: "fs-storage",
		ProxmoxVMStoragePool:  "vm-storage",
		EdgeAutoProvision:     true,
		EdgeProxyEnabled:      true,
		EdgeVMName:            "ludus-edge",
		EdgeVMIP:              "127.0.0.1",
		EdgeVMGateway:         "10.0.20.1",
		EdgeVMBridge:          "vmbr0",
		EdgeVMCIDRPrefix:      22,
		EdgeNATIP:             "192.0.2.254",
		EdgeNATMAC:            "02:1d:ed:6e:02:fe",
		EdgeISOPath:           isoFile,
		EdgeStateDir:          ctrlEdgeDir,
		EdgeProxyAddr:         liveEdgeAddr,
	}
	cfg.ApplyRemoteProxmoxDefaults()

	// Run Day-0 reconciliation: uploads ISO -> creates ludus-edge VM -> starts VM -> seals over :8444 -> writes wg_pool.json!
	if err := ReconcileEdgeVMAndProxy(context.Background(), &cfg); err != nil {
		t.Fatalf("ReconcileEdgeVMAndProxy failed: %v", err)
	}

	mu.Lock()
	gotCreateCalls := vmCreateCalls
	gotStartCalls := vmStartCalls
	gotISOs := len(uploadedISOs)
	formCopy := createdVMForm
	mu.Unlock()

	if gotISOs != 1 || gotCreateCalls != 1 || gotStartCalls != 1 {
		t.Fatalf("expected 1 ISO upload, 1 VM create, 1 VM start; got isos=%d create=%d start=%d",
			gotISOs, gotCreateCalls, gotStartCalls)
	}
	if formCopy.Get("pool") != "ADMIN" || formCopy.Get("memory") != "512" || formCopy.Get("cicustom") != "" {
		t.Fatalf("unexpected ludus-edge VM parameters (must use ADMIN pool, 512MB RAM, zero root-only cicustom): %v", formCopy)
	}
	if strings.Contains(formCopy.Get("sshkeys"), "+") {
		t.Fatalf("Proxmox sshkeys must percent-encode spaces as %%20, never '+': %q", formCopy.Get("sshkeys"))
	}
	if formCopy.Get("net1") != "virtio=02:1D:ED:6E:02:FE,bridge=ludusnat,mtu=1" {
		t.Fatalf("expected deterministic net1 MAC + mtu=1 on ludusnat, got %q", formCopy.Get("net1"))
	}
	if formCopy.Get("ipconfig0") != "ip=127.0.0.1/22,gw=10.0.20.1" {
		t.Fatalf("expected EdgeVMCIDRPrefix=22 in ipconfig0, got %q", formCopy.Get("ipconfig0"))
	}

	// Verify wg_pool.json was persisted and works with Phase 2 LoadWireGuardClientPool!
	pool, err := LoadWireGuardClientPool(cfg.WireguardPoolFile)
	if err != nil {
		t.Fatalf("LoadWireGuardClientPool after seal failed: %v", err)
	}
	if _, err := pool.DeriveClientPrivateKey(2); err != nil {
		t.Fatalf("DeriveClientPrivateKey(2) failed: %v", err)
	}

	// Second call to ReconcileEdgeVMAndProxy must hit the fast-path mTLS PING with zero additional Proxmox calls!
	if err := ReconcileEdgeVMAndProxy(context.Background(), &cfg); err != nil {
		t.Fatalf("second ReconcileEdgeVMAndProxy failed: %v", err)
	}
	mu.Lock()
	if vmCreateCalls != 1 || vmStartCalls != 1 {
		mu.Unlock()
		t.Fatalf("expected idempotent fast-path skip on second ReconcileEdgeVMAndProxy")
	}
	mu.Unlock()

	// Verify Packer port bitset allocator and BuildEdgeProxyEnvVars.
	ServerConfiguration = cfg
	ServerConfiguration.PackerHTTPPortMin = 8350
	ServerConfiguration.PackerHTTPPortMax = 8352
	p1, err := AcquirePackerReversePort()
	if err != nil || p1 != 8350 {
		t.Fatalf("expected first Packer port 8350, got %d (%v)", p1, err)
	}
	p2, _ := AcquirePackerReversePort()
	p3, _ := AcquirePackerReversePort()
	if p2 != 8351 || p3 != 8352 {
		t.Fatalf("unexpected Packer ports %d, %d", p2, p3)
	}
	if _, err := AcquirePackerReversePort(); err == nil {
		t.Fatalf("expected exhausted Packer port pool to error")
	}
	ReleasePackerReversePort(p2)
	p2Again, err := AcquirePackerReversePort()
	if err != nil || p2Again != 8351 {
		t.Fatalf("expected released port 8351 to be reallocated, got %d (%v)", p2Again, err)
	}
	ReleasePackerReversePort(p1)
	ReleasePackerReversePort(p2Again)
	ReleasePackerReversePort(p3)

	envVars := BuildEdgeProxyEnvVars()
	if !strings.Contains(envVars["ANSIBLE_SSH_ARGS"], "--proxy-dial %h %p") {
		t.Fatalf("expected ANSIBLE_SSH_ARGS to contain --proxy-dial, got %q", envVars["ANSIBLE_SSH_ARGS"])
	}
	if envVars["HTTP_PROXY"] == "" || envVars["HTTPS_PROXY"] == "" || !strings.Contains(envVars["NO_PROXY"], "127.0.0.1") {
		t.Fatalf("unexpected proxy env vars: %v", envVars)
	}
}
