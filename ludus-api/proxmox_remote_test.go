package ludusapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	goproxmox "github.com/luthermonson/go-proxmox"
)

func init() {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
}

type mockProxmoxServer struct {
	mu          sync.Mutex
	version     string
	nodes       []string
	users       map[string]map[string]string // userid -> fields
	passwords   map[string]string            // userid -> password
	tokens      map[string]string            // full-tokenid -> secret
	roles       map[string]string            // roleid -> privs
	groups      map[string]string            // groupid -> comment
	pools       map[string]string            // poolid -> comment
	sdnZones    map[string]string            // zone -> type
	sdnVNets    map[string]url.Values        // vnet -> form params
	acls            []url.Values
	sdnApplied      int
	tokenSeq        int
	rejectSimpleTag bool
}

func newMockProxmoxTLSServer(t *testing.T, version string, nodes []string) (*httptest.Server, *mockProxmoxServer) {
	t.Helper()
	m := &mockProxmoxServer{
		version:   version,
		nodes:     nodes,
		users:     map[string]map[string]string{"root@pam": {"userid": "root@pam"}},
		passwords: map[string]string{"root@pam": "root-secret-pw"},
		tokens:    map[string]string{},
		roles:     map[string]string{},
		groups:    map[string]string{},
		pools:     map[string]string{},
		sdnZones:  map[string]string{},
		sdnVNets:  map[string]url.Values{},
		rejectSimpleTag: true,
	}

	writeJSON := func(w http.ResponseWriter, status int, data interface{}) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": data})
	}
	writeErr := func(w http.ResponseWriter, status int, msg string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data":   nil,
			"errors": map[string]string{"detail": msg},
		})
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api2/json/") {
			http.NotFound(w, r)
			return
		}
		sub := strings.TrimPrefix(r.URL.Path, "/api2/json")

		var form url.Values
		if r.Method == http.MethodGet || r.Method == http.MethodDelete {
			form = r.URL.Query()
		} else {
			rawBody, _ := io.ReadAll(r.Body)
			form, _ = url.ParseQuery(string(rawBody))
		}

		// Public endpoint: ticket creation
		if sub == "/access/ticket" && r.Method == http.MethodPost {
			m.mu.Lock()
			defer m.mu.Unlock()
			user := form.Get("username")
			pw := form.Get("password")
			if expected, ok := m.passwords[user]; !ok || expected != pw {
				writeErr(w, http.StatusUnauthorized, "invalid credentials")
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{
				"ticket":              "PVE:" + user + ":MOCKTICKET",
				"CSRFPreventionToken": "CSRF-" + user,
				"username":            user,
			})
			return
		}

		// Authenticate via PVEAPIToken or PVEAuthCookie (+ CSRF check on writes)
		isTicketAuth := false
		var authPrincipal string
		if authHdr := r.Header.Get("Authorization"); strings.HasPrefix(authHdr, "PVEAPIToken=") {
			rawTok := strings.TrimPrefix(authHdr, "PVEAPIToken=")
			parts := strings.SplitN(rawTok, "=", 2)
			m.mu.Lock()
			expectedSecret, ok := m.tokens[parts[0]]
			m.mu.Unlock()
			if len(parts) != 2 || !ok || expectedSecret != parts[1] {
				writeErr(w, http.StatusUnauthorized, "invalid api token")
				return
			}
			authPrincipal = parts[0]
		} else if cookieHdr := r.Header.Get("Cookie"); strings.HasPrefix(cookieHdr, "PVEAuthCookie=PVE:") {
			trimmed := strings.TrimPrefix(cookieHdr, "PVEAuthCookie=PVE:")
			user := strings.TrimSuffix(trimmed, ":MOCKTICKET")
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				if r.Header.Get("CSRFPreventionToken") != "CSRF-"+user {
					writeErr(w, http.StatusForbidden, "missing or invalid CSRFPreventionToken")
					return
				}
			}
			isTicketAuth = true
			authPrincipal = user
		} else {
			writeErr(w, http.StatusUnauthorized, "unauthenticated")
			return
		}

		m.mu.Lock()
		defer m.mu.Unlock()

		switch {
		case sub == "/version" && r.Method == http.MethodGet:
			writeJSON(w, http.StatusOK, map[string]string{"version": m.version, "release": m.version})

		case sub == "/cluster/status" && r.Method == http.MethodGet:
			items := []map[string]string{}
			for _, n := range m.nodes {
				items = append(items, map[string]string{"type": "node", "name": n})
			}
			writeJSON(w, http.StatusOK, items)

		case sub == "/nodes" && r.Method == http.MethodGet:
			items := []map[string]string{}
			for _, n := range m.nodes {
				items = append(items, map[string]string{"node": n, "status": "online"})
			}
			writeJSON(w, http.StatusOK, items)

		case strings.HasPrefix(sub, "/nodes/") && strings.Contains(sub, "/tasks/") && strings.HasSuffix(sub, "/status"):
			writeJSON(w, http.StatusOK, map[string]string{"status": "stopped", "exitstatus": "OK"})

		case sub == "/access/password" && r.Method == http.MethodPut:
			// Real Proxmox VE forbids API tokens on /access/password!
			if !isTicketAuth {
				writeErr(w, http.StatusForbidden, "API tokens cannot change passwords")
				return
			}
			target := form.Get("userid")
			if authPrincipal != "root@pam" && authPrincipal != target {
				writeErr(w, http.StatusForbidden, "insufficient privilege to change another user's password")
				return
			}
			m.passwords[target] = form.Get("password")
			writeJSON(w, http.StatusOK, nil)

		case sub == "/access/roles" && r.Method == http.MethodPost:
			m.roles[form.Get("roleid")] = form.Get("privs")
			writeJSON(w, http.StatusOK, nil)

		case strings.HasPrefix(sub, "/access/roles/"):
			roleID := strings.TrimPrefix(sub, "/access/roles/")
			if r.Method == http.MethodGet {
				privs, ok := m.roles[roleID]
				if !ok {
					writeErr(w, http.StatusInternalServerError, "role does not exist")
					return
				}
				writeJSON(w, http.StatusOK, map[string]int{privs: 1})
			} else if r.Method == http.MethodPut {
				m.roles[roleID] = form.Get("privs")
				writeJSON(w, http.StatusOK, nil)
			}

		case sub == "/access/groups" && r.Method == http.MethodPost:
			m.groups[form.Get("groupid")] = form.Get("comment")
			writeJSON(w, http.StatusOK, nil)

		case strings.HasPrefix(sub, "/access/groups/"):
			gid := strings.TrimPrefix(sub, "/access/groups/")
			if _, ok := m.groups[gid]; !ok {
				writeErr(w, http.StatusInternalServerError, "group not found")
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"groupid": gid})

		case sub == "/pools" && r.Method == http.MethodGet:
			list := []map[string]string{}
			for pid := range m.pools {
				list = append(list, map[string]string{"poolid": pid})
			}
			writeJSON(w, http.StatusOK, list)

		case sub == "/pools" && r.Method == http.MethodPost:
			m.pools[form.Get("poolid")] = form.Get("comment")
			writeJSON(w, http.StatusOK, nil)

		case sub == "/access/acl" && r.Method == http.MethodPut:
			m.acls = append(m.acls, form)
			writeJSON(w, http.StatusOK, nil)

		case sub == "/access/users" && r.Method == http.MethodPost:
			uid := form.Get("userid")
			m.users[uid] = map[string]string{
				"userid": uid,
				"groups": form.Get("groups"),
			}
			if pw := form.Get("password"); pw != "" {
				m.passwords[uid] = pw
			}
			writeJSON(w, http.StatusOK, nil)

		case strings.HasPrefix(sub, "/access/users/") && strings.Contains(sub, "/token/"):
			rest := strings.TrimPrefix(sub, "/access/users/")
			idx := strings.Index(rest, "/token/")
			uid, _ := url.PathUnescape(rest[:idx])
			tokName, _ := url.PathUnescape(rest[idx+len("/token/"):])
			fullID := uid + "!" + tokName
			switch r.Method {
			case http.MethodPost:
				if _, exists := m.tokens[fullID]; exists {
					writeErr(w, http.StatusBadRequest, "token already exists")
					return
				}
				m.tokenSeq++
				secret := fmt.Sprintf("sec-%d-%s", m.tokenSeq, tokName)
				m.tokens[fullID] = secret
				writeJSON(w, http.StatusOK, map[string]string{
					"full-tokenid": fullID,
					"value":        secret,
				})
			case http.MethodDelete:
				delete(m.tokens, fullID)
				writeJSON(w, http.StatusOK, nil)
			}

		case strings.HasPrefix(sub, "/access/users/"):
			uid, _ := url.PathUnescape(strings.TrimPrefix(sub, "/access/users/"))
			switch r.Method {
			case http.MethodGet:
				u, ok := m.users[uid]
				if !ok {
					writeErr(w, http.StatusInternalServerError, "no such user")
					return
				}
				writeJSON(w, http.StatusOK, u)
			case http.MethodPut:
				if _, ok := m.users[uid]; !ok {
					writeErr(w, http.StatusInternalServerError, "no such user")
					return
				}
				m.users[uid]["groups"] = form.Get("groups")
				writeJSON(w, http.StatusOK, nil)
			}

		case sub == "/cluster/sdn/zones" && r.Method == http.MethodGet:
			zones := []map[string]string{}
			for z, zt := range m.sdnZones {
				zones = append(zones, map[string]string{"zone": z, "type": zt})
			}
			writeJSON(w, http.StatusOK, zones)

		case sub == "/cluster/sdn/zones" && r.Method == http.MethodPost:
			m.sdnZones[form.Get("zone")] = form.Get("type")
			writeJSON(w, http.StatusOK, nil)

		case sub == "/cluster/sdn/vnets" && r.Method == http.MethodGet:
			vnets := []map[string]string{}
			for v, vf := range m.sdnVNets {
				vnets = append(vnets, map[string]string{"vnet": v, "zone": vf.Get("zone")})
			}
			writeJSON(w, http.StatusOK, vnets)

		case sub == "/cluster/sdn/vnets" && r.Method == http.MethodPost:
			zone := form.Get("zone")
			zType := m.sdnZones[zone]
			if m.rejectSimpleTag && zType == "simple" && form.Get("tag") != "" {
				writeErr(w, http.StatusBadRequest, "simple SDN zone does not allow VNet tag property")
				return
			}
			m.sdnVNets[form.Get("vnet")] = form
			writeJSON(w, http.StatusOK, nil)

		case sub == "/cluster/sdn" && r.Method == http.MethodPut:
			m.sdnApplied++
			node := "pve"
			if len(m.nodes) > 0 {
				node = m.nodes[0]
			}
			writeJSON(w, http.StatusOK, fmt.Sprintf("UPID:%s:00001234:00005678:67000000:srvreload:networking:root@pam:", node))

		default:
			writeErr(w, http.StatusNotFound, "unhandled path "+sub)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, m
}

func writeSecretFileForTest(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "proxmox-admin-pass")
	if err := os.WriteFile(p, []byte(content+"\n"), 0o600); err != nil {
		t.Fatalf("writing secret file: %v", err)
	}
	return p
}

func TestRemoteProxmoxConfigNormalization(t *testing.T) {
	tlsVerifyFalse := false
	cfg := Configuration{
		RemoteProxmox:     true,
		ProxmoxURL:        "https://10.0.20.12:8006/api2/json/",
		ProxmoxNode:       "pve-prod-02",
		ProxmoxTLSVerify:  &tlsVerifyFalse,
		LudusNATInterface: "vmbr1000", // legacy host default should normalize to "ludusnat"
	}
	cfg.ApplyRemoteProxmoxDefaults()
	if !cfg.ProxmoxInvalidCert {
		t.Fatal("expected ProxmoxTLSVerify=false to set ProxmoxInvalidCert=true")
	}
	if got := cfg.ProxmoxURL; got != "https://10.0.20.12:8006" {
		t.Fatalf("expected normalized ProxmoxURL='https://10.0.20.12:8006', got %q", got)
	}

	if got := cfg.ProxmoxRealm; got != "pve" {
		t.Fatalf("expected ProxmoxRealm='pve', got %q", got)
	}
	if got := cfg.LudusNATInterface; got != "ludusnat" {
		t.Fatalf("expected LudusNATInterface='ludusnat', got %q", got)
	}
	if got := cfg.ProxmoxHostname; got != "10.0.20.12" {
		t.Fatalf("expected ProxmoxHostname='10.0.20.12', got %q", got)
	}
	if got := cfg.EffectiveProxmoxAdminUser(); got != "root@pam" {
		t.Fatalf("expected default admin user 'root@pam', got %q", got)
	}

	ConfigMu.Lock()
	prev := ServerConfiguration
	ServerConfiguration = cfg
	ConfigMu.Unlock()
	t.Cleanup(func() {
		ConfigMu.Lock()
		ServerConfiguration = prev
		ConfigMu.Unlock()
	})

	useSDN, err := ShouldUseSDN()
	if err != nil || !useSDN {
		t.Fatalf("ShouldUseSDN() = (%v, %v), want (true, nil)", useSDN, err)
	}
}

func TestBuildVNetOptionsForZone(t *testing.T) {
	// Standalone simple zone must omit Tag (Tag == 0) while keeping VlanAware enabled.
	simpleNAT, err := BuildVNetOptionsForZone("ludusnat", "ludus", "simple", true, 0, 0)
	if err != nil {
		t.Fatalf("simple NAT VNet failed: %v", err)
	}
	if simpleNAT.Tag != 0 || !simpleNAT.VlanAware {
		t.Fatalf("simple NAT VNet got Tag=%d VlanAware=%v, want Tag=0 VlanAware=true", simpleNAT.Tag, simpleNAT.VlanAware)
	}

	simpleRange, err := BuildVNetOptionsForZone("r3", "ludus", "simple", false, 1000, 3)
	if err != nil {
		t.Fatalf("simple range VNet failed: %v", err)
	}
	if simpleRange.Tag != 0 || !simpleRange.VlanAware {
		t.Fatalf("simple range VNet got Tag=%d VlanAware=%v, want Tag=0 VlanAware=true", simpleRange.Tag, simpleRange.VlanAware)
	}

	// Cluster VXLAN zone sets VNI 16777215 on ludusnat and vxlanTagBase+N on range VNets.
	vxlanNAT, err := BuildVNetOptionsForZone("ludusnat", "ludus", "vxlan", true, 1000, 0)
	if err != nil {
		t.Fatalf("vxlan NAT VNet failed: %v", err)
	}
	if vxlanNAT.Tag != 16777215 || !vxlanNAT.VlanAware {
		t.Fatalf("vxlan NAT VNet got Tag=%d VlanAware=%v, want Tag=16777215 VlanAware=true", vxlanNAT.Tag, vxlanNAT.VlanAware)
	}

	vxlanRange, err := BuildVNetOptionsForZone("r3", "ludus", "vxlan", false, 1000, 3)
	if err != nil {
		t.Fatalf("vxlan range VNet failed: %v", err)
	}
	if vxlanRange.Tag != 1003 || !vxlanRange.VlanAware {
		t.Fatalf("vxlan range VNet got Tag=%d VlanAware=%v, want Tag=1003 VlanAware=true", vxlanRange.Tag, vxlanRange.VlanAware)
	}

	// QinQ / VLAN zones enforce 802.1Q 1..4094 limits.
	if _, err := BuildVNetOptionsForZone("r1", "ludus", "qinq", false, 5000, 1); err == nil {
		t.Fatal("expected error for out-of-range 802.1Q tag on qinq zone")
	}
}

func TestBootstrapRemoteProxmoxStandaloneSimpleSDN(t *testing.T) {
	srv, mock := newMockProxmoxTLSServer(t, "9.0.4", []string{"pve-prod-02"})
	pwFile := writeSecretFileForTest(t, "root-secret-pw")

	cfg := &Configuration{
		RemoteProxmox:            true,
		ProxmoxURL:               srv.URL,
		ProxmoxNode:              "pve-prod-02",
		ProxmoxInvalidCert:       true, // skip TLS verify for httptest self-signed cert
		ProxmoxAdminUser:         "root@pam",
		ProxmoxAdminPasswordFile: pwFile,
		ProxmoxVMStoragePool:     "local-zfs",
		ProxmoxISOStoragePool:    "local",
		SDNZone:                  "ludus",
	}
	cfg.ApplyRemoteProxmoxDefaults()

	ctx := context.Background()
	if err := BootstrapRemoteProxmox(ctx, cfg); err != nil {
		t.Fatalf("BootstrapRemoteProxmox standalone failed: %v", err)
	}

	mock.mu.Lock()
	defer mock.mu.Unlock()

	if mock.sdnZones["ludus"] != "simple" {
		t.Fatalf("expected auto-created standalone SDN zone 'ludus' of type 'simple', got %q", mock.sdnZones["ludus"])
	}
	natVNet, ok := mock.sdnVNets["ludusnat"]
	if !ok {
		t.Fatal("expected 'ludusnat' VNet to be created")
	}
	if natVNet.Get("tag") != "" {
		t.Fatalf("expected tagless ludusnat on simple zone, got tag=%q", natVNet.Get("tag"))
	}
	if natVNet.Get("vlanaware") != "1" {
		t.Fatalf("expected vlanaware=1 on ludusnat, got %q", natVNet.Get("vlanaware"))
	}
	if mock.sdnApplied == 0 {
		t.Fatal("expected PUT /cluster/sdn reload to be triggered")
	}
	for _, role := range []string{"ResourceAudit", "DatastoreUser", "AccessNetwork"} {
		if _, exists := mock.roles[role]; !exists {
			t.Fatalf("missing expected Proxmox custom role %q", role)
		}
	}
	for _, grp := range []string{"ludus_users", "ludus_admins"} {
		if _, exists := mock.groups[grp]; !exists {
			t.Fatalf("missing expected Proxmox group %q", grp)
		}
	}
	for _, pool := range []string{"SHARED", "ADMIN"} {
		if _, exists := mock.pools[pool]; !exists {
			t.Fatalf("missing expected Proxmox pool %q", pool)
		}
	}
}

func TestBootstrapRemoteProxmoxClusterRequiresZoneAndTagsVNet(t *testing.T) {
	srv, mock := newMockProxmoxTLSServer(t, "8.4.1", []string{"pve-01", "pve-02"})
	pwFile := writeSecretFileForTest(t, "root-secret-pw")

	cfg := &Configuration{
		RemoteProxmox:            true,
		ProxmoxURL:               srv.URL,
		ProxmoxNode:              "pve-01",
		ProxmoxInvalidCert:       true,
		ProxmoxAdminPasswordFile: pwFile,
		ProxmoxVMStoragePool:     "ceph-vm",
		ProxmoxISOStoragePool:    "cephfs",
		SDNZone:                  "ludus",
	}
	cfg.ApplyRemoteProxmoxDefaults()

	ctx := context.Background()
	// Without a pre-configured VXLAN/EVPN zone, multi-node cluster bootstrap must fail closed.
	if err := BootstrapRemoteProxmox(ctx, cfg); err == nil {
		t.Fatal("expected BootstrapRemoteProxmox to fail when multi-node cluster lacks pre-created VXLAN/EVPN zone")
	}

	// Pre-create VXLAN zone on cluster and re-run bootstrap.
	mock.mu.Lock()
	mock.sdnZones["ludus"] = "vxlan"
	mock.mu.Unlock()

	if err := BootstrapRemoteProxmox(ctx, cfg); err != nil {
		t.Fatalf("BootstrapRemoteProxmox cluster failed after VXLAN zone creation: %v", err)
	}

	mock.mu.Lock()
	defer mock.mu.Unlock()
	natVNet := mock.sdnVNets["ludusnat"]
	if natVNet.Get("tag") != "16777215" {
		t.Fatalf("expected VNI tag 16777215 on cluster VXLAN ludusnat, got %q", natVNet.Get("tag"))
	}

	// Verify node-scoped ACLs were applied to BOTH cluster nodes.
	nodesCovered := map[string]bool{}
	for _, acl := range mock.acls {
		p := acl.Get("path")
		if strings.HasPrefix(p, "/nodes/") {
			nodesCovered[strings.TrimPrefix(p, "/nodes/")] = true
		}
	}
	if !nodesCovered["pve-01"] || !nodesCovered["pve-02"] {
		t.Fatalf("expected node ACLs on both pve-01 and pve-02, got %v", nodesCovered)
	}
}

func TestRemoteProxmoxUserLifecycleAndTokenRotation(t *testing.T) {
	srv, mock := newMockProxmoxTLSServer(t, "9.0.4", []string{"pve-prod-02"})
	pwFile := writeSecretFileForTest(t, "root-secret-pw")

	cfg := &Configuration{
		RemoteProxmox:            true,
		ProxmoxURL:               srv.URL,
		ProxmoxNode:              "pve-prod-02",
		ProxmoxInvalidCert:       true,
		ProxmoxAdminPasswordFile: pwFile,
		ProxmoxVMStoragePool:     "local-zfs",
		ProxmoxISOStoragePool:    "local",
	}
	cfg.ApplyRemoteProxmoxDefaults()

	// 1. Create and rotate root API token via HTTPS
	tokID1, sec1, err := createRootAPITokenViaAPI(cfg)
	if err != nil {
		t.Fatalf("createRootAPITokenViaAPI #1 failed: %v", err)
	}
	if tokID1 != "root@pam!ludus-token" || sec1 == "" {
		t.Fatalf("unexpected root token #1: id=%q sec=%q", tokID1, sec1)
	}
	tokID2, sec2, err := createRootAPITokenViaAPI(cfg)
	if err != nil {
		t.Fatalf("createRootAPITokenViaAPI #2 (rotation) failed: %v", err)
	}
	if tokID2 != "root@pam!ludus-token" || sec2 == "" || sec2 == sec1 {
		t.Fatalf("expected rotated secret on #2, got sec1=%q sec2=%q", sec1, sec2)
	}

	// 2. Provision @pve Ludus user + pool/storage ACLs without PAM or pveum
	if err := ensureProxmoxUserAndACLsViaAPI(cfg, "caleb", "pve", "init-user-pw", "CL", true, true); err != nil {
		t.Fatalf("ensureProxmoxUserAndACLsViaAPI failed: %v", err)
	}

	mock.mu.Lock()
	u, exists := mock.users["caleb@pve"]
	pw := mock.passwords["caleb@pve"]
	mock.mu.Unlock()
	if !exists || !strings.Contains(u["groups"], "ludus_users") || !strings.Contains(u["groups"], "ludus_admins") {
		t.Fatalf("unexpected @pve user state: %+v", u)
	}
	if pw != "init-user-pw" {
		t.Fatalf("expected caleb@pve password to be set, got %q", pw)
	}

	// 3. Mint and rotate per-user @pve API token using user's own @pve credentials
	uTok1, uSec1, err := createProxmoxUserAPITokenViaAPI(cfg, "caleb", "pve", "init-user-pw")
	if err != nil {
		t.Fatalf("createProxmoxUserAPITokenViaAPI #1 failed: %v", err)
	}
	if uTok1 != "caleb@pve!ludus-token" || uSec1 == "" {
		t.Fatalf("unexpected user token: id=%q sec=%q", uTok1, uSec1)
	}
	uTok2, uSec2, err := createProxmoxUserAPITokenViaAPI(cfg, "caleb", "pve", "init-user-pw")
	if err != nil {
		t.Fatalf("createProxmoxUserAPITokenViaAPI #2 (rotation) failed: %v", err)
	}
	if uTok2 != "caleb@pve!ludus-token" || uSec2 == uSec1 {
		t.Fatalf("expected rotated user token secret, got %q vs %q", uSec1, uSec2)
	}

	// 4. Self-service password rotation fallback (even without admin password file)
	noAdminFileCfg := *cfg
	noAdminFileCfg.ProxmoxAdminPasswordFile = filepath.Join(t.TempDir(), "nonexistent")
	if err := setProxmoxPasswordViaAPI(&noAdminFileCfg, "caleb", "pve", "rotated-user-pw", "init-user-pw"); err != nil {
		t.Fatalf("self-ticket setProxmoxPasswordViaAPI failed: %v", err)
	}
	mock.mu.Lock()
	finalPW := mock.passwords["caleb@pve"]
	mock.mu.Unlock()
	if finalPW != "rotated-user-pw" {
		t.Fatalf("expected rotated password 'rotated-user-pw', got %q", finalPW)
	}
}

func TestClusterNodePinningAndAllowlist(t *testing.T) {
	clusterNodes := goproxmox.NodeStatuses{
		{Node: "pve-prod-01", Status: "online", CPU: 0.05, Mem: 8, MaxMem: 128},  // very idle, forbidden
		{Node: "pve-prod-02", Status: "online", CPU: 0.45, Mem: 72, MaxMem: 128}, // busier, designated Ludus node
		{Node: "pve-prod-03", Status: "online", CPU: 0.10, Mem: 16, MaxMem: 128}, // idle, forbidden
	}

	// 1. Unrestricted cluster picks lowest-score node (pve-prod-01)
	gotUnrestricted, err := selectOptimalNodeFromStatuses(clusterNodes, nil)
	if err != nil || gotUnrestricted != "pve-prod-01" {
		t.Fatalf("unrestricted selectOptimalNodeFromStatuses = (%q, %v), want (pve-prod-01, nil)", gotUnrestricted, err)
	}

	// 2. proxmox_pin_to_node: true strictly pins placement, validation, and bootstrap ACLs to pve-prod-02
	srv, mock := newMockProxmoxTLSServer(t, "9.2.26", []string{"pve-prod-01", "pve-prod-02", "pve-prod-03"})
	mock.sdnZones["ludus"] = "vxlan"
	pwFile := writeSecretFileForTest(t, "root-secret-pw")

	pinnedCfg := &Configuration{
		RemoteProxmox:            true,
		ProxmoxURL:               srv.URL,
		ProxmoxNode:              "pve-prod-02",
		ProxmoxPinToNode:         true,
		ClusterMode:              true,
		SDNZone:                  "ludus",
		ProxmoxInvalidCert:       true,
		ProxmoxAdminPasswordFile: pwFile,
		ProxmoxVMStoragePool:     "vm-storage",
		ProxmoxISOStoragePool:    "fs-storage",
	}
	pinnedCfg.ApplyRemoteProxmoxDefaults()

	allowed := pinnedCfg.EffectiveAllowedProxmoxNodes()
	if len(allowed) != 1 || allowed[0] != "pve-prod-02" {
		t.Fatalf("EffectiveAllowedProxmoxNodes = %v, want [pve-prod-02]", allowed)
	}
	if pinnedCfg.IsProxmoxNodeAllowed("pve-prod-01") || pinnedCfg.IsProxmoxNodeAllowed("pve-prod-03") || !pinnedCfg.IsProxmoxNodeAllowed("pve-prod-02") {
		t.Fatalf("IsProxmoxNodeAllowed failed to restrict to pve-prod-02")
	}

	gotPinned, err := selectOptimalNodeFromStatuses(clusterNodes, allowed)
	if err != nil || gotPinned != "pve-prod-02" {
		t.Fatalf("pinned selectOptimalNodeFromStatuses = (%q, %v), want (pve-prod-02, nil)", gotPinned, err)
	}

	// Fail closed if pinned node is offline rather than spilling onto pve-prod-01/03
	offlineNodes := goproxmox.NodeStatuses{
		{Node: "pve-prod-01", Status: "online", CPU: 0.05, Mem: 8, MaxMem: 128},
		{Node: "pve-prod-02", Status: "offline", CPU: 0, Mem: 0, MaxMem: 128},
	}
	if _, err := selectOptimalNodeFromStatuses(offlineNodes, allowed); err == nil {
		t.Fatalf("expected error when pinned node pve-prod-02 is offline, got nil")
	}

	// validateTargetNode rejects forbidden cluster nodes before hitting Proxmox
	ConfigMu.Lock()
	prevCfg := ServerConfiguration
	ServerConfiguration = *pinnedCfg
	ConfigMu.Unlock()
	defer func() {
		ConfigMu.Lock()
		ServerConfiguration = prevCfg
		ConfigMu.Unlock()
	}()
	if err := validateTargetNode(nil, "pve-prod-01"); err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Fatalf("expected validateTargetNode to reject pve-prod-01 when pinned, got %v", err)
	}

	// BootstrapRemoteProxmox scopes /nodes/* ACLs exclusively to pve-prod-02
	if err := BootstrapRemoteProxmox(context.Background(), pinnedCfg); err != nil {
		t.Fatalf("BootstrapRemoteProxmox (pinned cluster) failed: %v", err)
	}
	mock.mu.Lock()
	defer mock.mu.Unlock()
	for _, acl := range mock.acls {
		p := acl.Get("path")
		if strings.HasPrefix(p, "/nodes/") && p != "/nodes/pve-prod-02" {
			t.Fatalf("expected /nodes/* ACLs only on /nodes/pve-prod-02 when pinned, got %q", p)
		}
	}
}

