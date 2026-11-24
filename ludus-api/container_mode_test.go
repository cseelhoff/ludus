package ludusapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ludusapi/models"

	"github.com/pocketbase/pocketbase/core"
)

func TestContainerAndServiceTokenConfigDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "db-key")
	expectedKey := "0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(keyFile, []byte(expectedKey+"\n"), 0440); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	tlsFalse := false
	cfg := Configuration{
		ContainerMode:             true,
		TLSEnabled:                &tlsFalse,
		ProxmoxURL:                "https://10.0.20.12:8006/api2/json/",
		ProxmoxNode:               "pve-prod-02",
		ProxmoxAPITokenID:         "ludus-svc@pve!controller",
		DatabaseEncryptionKeyFile: keyFile,
		DataDirectory:             filepath.Join(tmpDir, "db"),
		EdgeAutoProvision:         true,
		EdgeProxyEnabled:          true,
		EdgeVMIP:                  "10.0.20.181",
	}
	cfg.ApplyRemoteProxmoxDefaults()
	if err := cfg.LoadEncryptionKeyFromFileIfConfigured(); err != nil {
		t.Fatalf("LoadEncryptionKeyFromFileIfConfigured: %v", err)
	}

	if !cfg.RemoteProxmox {
		t.Fatalf("expected ContainerMode to force RemoteProxmox=true")
	}
	if !cfg.IsServiceTokenAuthMode() || cfg.ProxmoxAuthMode != ProxmoxAuthModeServiceToken {
		t.Fatalf("expected service_token auth mode, got %q", cfg.ProxmoxAuthMode)
	}
	if cfg.IsTLSEnabled() {
		t.Fatalf("expected IsTLSEnabled()=false when tls_enabled is explicitly false")
	}
	if cfg.LudusNATInterface != NATVNetName {
		t.Fatalf("expected LudusNATInterface=%q, got %q", NATVNetName, cfg.LudusNATInterface)
	}
	if cfg.ProxmoxHostname != "10.0.20.12" {
		t.Fatalf("expected ProxmoxHostname=10.0.20.12, got %q", cfg.ProxmoxHostname)
	}
	if cfg.DatabaseEncryptionKey != expectedKey {
		t.Fatalf("expected DatabaseEncryptionKey loaded from file, got %q", cfg.DatabaseEncryptionKey)
	}
	if cfg.EdgeProxyAddr != "10.0.20.181:8444" {
		t.Fatalf("expected derived EdgeProxyAddr=10.0.20.181:8444, got %q", cfg.EdgeProxyAddr)
	}
	if cfg.WireguardPoolFile != filepath.Join(tmpDir, "db", "edge", "wireguard-pool.json") {
		t.Fatalf("unexpected WireguardPoolFile %q", cfg.WireguardPoolFile)
	}
}

func TestVerifyProxmoxServiceTokenZeroIAMMutations(t *testing.T) {
	srv, mock := newMockProxmoxTLSServer(t, "8.3.2", []string{"pve-prod-01", "pve-prod-02"})
	defer srv.Close()

	const svcTokenID = "ludus-svc@pve!controller"
	const svcSecret = "d13a9f70-secret-token-value"
	mock.tokens[svcTokenID] = svcSecret
	mock.sdnZones["ludus"] = "vxlan"

	// Simulate read-only Compose secret mount permissions (0440) allowed in ContainerMode.
	secretPath := filepath.Join(t.TempDir(), "proxmox-token")
	if err := os.WriteFile(secretPath, []byte(svcSecret+"\n"), 0440); err != nil {
		t.Fatalf("write token secret: %v", err)
	}

	cfg := &Configuration{
		ContainerMode:      true,
		ProxmoxAuthMode:    ProxmoxAuthModeServiceToken,
		ProxmoxURL:         srv.URL,
		ProxmoxInvalidCert: true,
		ProxmoxNode:        "pve-prod-02",
		ProxmoxAPITokenID:  svcTokenID,
		ProxmoxAPITokenFile: secretPath,
		SDNZone:            "ludus",
	}

	// BootstrapRemoteProxmox must delegate to VerifyProxmoxServiceToken without any admin password.
	if err := BootstrapRemoteProxmox(context.Background(), cfg); err != nil {
		t.Fatalf("BootstrapRemoteProxmox (service_token): %v", err)
	}

	mock.mu.Lock()
	_, hasShared := mock.pools["SHARED"]
	_, hasAdmin := mock.pools["ADMIN"]
	_, hasNATVNet := mock.sdnVNets[NATVNetName]
	roleCount, groupCount, aclCount, userCount := len(mock.roles), len(mock.groups), len(mock.acls), len(mock.users)
	mock.mu.Unlock()

	if !hasShared {
		t.Fatalf("expected SHARED pool to be reconciled")
	}
	if !hasAdmin {
		t.Fatalf("expected ADMIN pool to be reconciled")
	}
	if !hasNATVNet {
		t.Fatalf("expected %s SDN VNet to be reconciled", NATVNetName)
	}
	if roleCount != 0 || groupCount != 0 || aclCount != 0 || userCount != 1 {
		t.Fatalf("expected zero Proxmox IAM/ACL mutations in service_token mode; got roles=%d groups=%d acls=%d users=%d",
			roleCount, groupCount, aclCount, userCount)
	}

	// Verify node visibility check catches invisible target nodes.
	badCfg := *cfg
	badCfg.ProxmoxNode = "pve-nonexistent"
	if err := VerifyProxmoxServiceToken(context.Background(), &badCfg); err == nil || !strings.Contains(err.Error(), "pve-nonexistent") {
		t.Fatalf("expected invisible proxmox_node error, got %v", err)
	}
}

func TestServiceTokenCredentialResolutionAndIAMNoOps(t *testing.T) {
	ConfigMu.Lock()
	origCfg := ServerConfiguration
	origSDN := UseSDN
	ConfigMu.Unlock()
	t.Cleanup(func() {
		ConfigMu.Lock()
		ServerConfiguration = origCfg
		UseSDN = origSDN
		ConfigMu.Unlock()
	})

	secretPath := filepath.Join(t.TempDir(), "svc-token")
	if err := os.WriteFile(secretPath, []byte("shared-token-secret\n"), 0400); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	ConfigMu.Lock()
	ServerConfiguration = Configuration{
		ContainerMode:       true,
		ProxmoxAuthMode:     ProxmoxAuthModeServiceToken,
		ProxmoxAPITokenID:   "ludus-svc@pve!controller",
		ProxmoxAPITokenFile: secretPath,
	}
	ServerConfiguration.ApplyRemoteProxmoxDefaults()
	UseSDN = true
	ConfigMu.Unlock()

	col := core.NewBaseCollection("users")
	rec := core.NewRecord(col)
	rec.Set("userID", "CA")
	rec.Set("proxmoxUsername", "caleb")
	rec.Set("proxmoxRealm", "pve")
	u := &models.User{}
	u.SetProxyRecord(rec)

	// Per-user workspace slug stays "caleb", while Proxmox API principal matches the service token prefix.
	apiUser, fullTokenID, secret, err := ResolveProxmoxCredentialsForUser(u)
	if err != nil {
		t.Fatalf("ResolveProxmoxCredentialsForUser: %v", err)
	}
	if u.ProxmoxUsername() != "caleb" {
		t.Fatalf("expected per-user workspace slug 'caleb', got %q", u.ProxmoxUsername())
	}
	if apiUser != "ludus-svc@pve" || fullTokenID != "ludus-svc@pve!controller" || secret != "shared-token-secret" {
		t.Fatalf("unexpected credentials: apiUser=%q fullTokenID=%q secret=%q", apiUser, fullTokenID, secret)
	}

	// All Proxmox IAM/ACL helpers must short-circuit cleanly without touching Proxmox or PocketBase app.
	if err := giveUserAccessToRange("caleb", "pve", "CA", 1); err != nil {
		t.Fatalf("giveUserAccessToRange: %v", err)
	}
	if err := removeUserAccessFromRange("caleb", "pve", "CA", 1); err != nil {
		t.Fatalf("removeUserAccessFromRange: %v", err)
	}
	if err := createGroupInProxmox("red_team-01"); err != nil {
		t.Fatalf("createGroupInProxmox valid: %v", err)
	}
	if err := createGroupInProxmox("invalid group!"); err == nil {
		t.Fatalf("expected group name regex validation to still reject invalid group names")
	}
	if err := removeGroupFromProxmox("red_team-01"); err != nil {
		t.Fatalf("removeGroupFromProxmox: %v", err)
	}
	if err := addUserToGroupInProxmox("caleb", "pve", "red_team-01"); err != nil {
		t.Fatalf("addUserToGroupInProxmox: %v", err)
	}
	if err := removeUserFromGroupInProxmox("caleb", "pve", "red_team-01"); err != nil {
		t.Fatalf("removeUserFromGroupInProxmox: %v", err)
	}
	if err := grantGroupAccessToRangeInProxmox("red_team-01", "CA", 1); err != nil {
		t.Fatalf("grantGroupAccessToRangeInProxmox: %v", err)
	}
	if err := revokeGroupAccessToRangeInProxmox("red_team-01", "CA", 1); err != nil {
		t.Fatalf("revokeGroupAccessToRangeInProxmox: %v", err)
	}
	if err := removeUserFromProxmox("caleb", "pve"); err != nil {
		t.Fatalf("removeUserFromProxmox: %v", err)
	}
	if err := setProxmoxSystemPassword("caleb", "pve", "new-pw"); err != nil {
		t.Fatalf("setProxmoxSystemPassword: %v", err)
	}
}

func TestProcessRoleExplicitOverride(t *testing.T) {
	t.Cleanup(ResetProcessRole)

	SetAdminProcess(true)
	if !IsAdminProcess() {
		t.Fatalf("expected IsAdminProcess()=true after SetAdminProcess(true)")
	}

	SetAdminProcess(false)
	if IsAdminProcess() {
		t.Fatalf("expected IsAdminProcess()=false after SetAdminProcess(false)")
	}
}

func TestContainerUserWorkspaceLifecycle(t *testing.T) {
	baseDir := t.TempDir()
	extraVars := map[string]interface{}{
		"username":               "caleb",
		"user_id":                "CA",
		"user_has_default_range": true,
	}

	if err := provisionContainerUserWorkspaceAt(baseDir, extraVars); err != nil {
		t.Fatalf("provisionContainerUserWorkspaceAt: %v", err)
	}

	expectedDirs := []string{
		filepath.Join(baseDir, "users", "caleb", "packer", "tmp"),
		filepath.Join(baseDir, "users", "caleb", "packer", "packer_cache"),
		filepath.Join(baseDir, "users", "caleb", ".ansible", "cp"),
		filepath.Join(baseDir, "users", "caleb", ".ansible", "roles"),
		filepath.Join(baseDir, "users", "caleb", ".ansible", "collections"),
	}
	for _, d := range expectedDirs {
		if info, err := os.Stat(d); err != nil || !info.IsDir() {
			t.Fatalf("expected directory %s to exist (err=%v)", d, err)
		}
	}
	if !FileExists(filepath.Join(baseDir, "ranges", "CA", "range-config.yml")) {
		t.Fatalf("expected range-config.yml to exist")
	}

	rangeCfg, err := os.ReadFile(filepath.Join(baseDir, "ranges", "CA", "range-config.yml"))
	if err != nil {
		t.Fatalf("read range-config.yml: %v", err)
	}
	if !strings.Contains(string(rangeCfg), "CA-kali") {
		t.Fatalf("expected rendered range-config.yml to substitute user_id CA, got:\n%s", string(rangeCfg))
	}

	for _, bad := range []string{"", ".", "..", "root", "../escape", "a/b"} {
		if err := provisionContainerUserWorkspaceAt(baseDir, map[string]interface{}{"username": bad}); err == nil {
			t.Fatalf("expected invalid username %q to be rejected", bad)
		}
		if err := removeContainerUserWorkspaceAt(baseDir, map[string]interface{}{"username": bad}); err == nil {
			t.Fatalf("expected invalid username %q removal to be rejected", bad)
		}
	}

	if err := removeContainerUserWorkspaceAt(baseDir, map[string]interface{}{"username": "caleb"}); err != nil {
		t.Fatalf("removeContainerUserWorkspaceAt: %v", err)
	}
	if _, err := os.Stat(filepath.Join(baseDir, "users", "caleb")); !os.IsNotExist(err) {
		t.Fatalf("expected user workspace directory to be removed, stat err=%v", err)
	}
	// Default range directory is managed separately by DeleteRange, matching del-user.yml behavior.
	if !FileExists(filepath.Join(baseDir, "ranges", "CA", "range-config.yml")) {
		t.Fatalf("expected range directory to remain untouched by user workspace removal")
	}
}
