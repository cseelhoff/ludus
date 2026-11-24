package ludusapi

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
	"ludusapi/models"

	"github.com/pocketbase/pocketbase/core"
)

func TestWireGuardPoolKeyDerivationAndSecretSeparation(t *testing.T) {
	bundle, err := GenerateEdgeWireGuardBundle("10.0.20.181:51820", 51820, 250)
	if err != nil {
		t.Fatalf("GenerateEdgeWireGuardBundle failed: %v", err)
	}

	tmpDir := t.TempDir()
	wgConfPath := filepath.Join(tmpDir, "wg0.conf")
	poolPath := filepath.Join(tmpDir, "wg_pool.json")
	if err := WriteWireGuardBundleFiles(wgConfPath, poolPath, bundle); err != nil {
		t.Fatalf("WriteWireGuardBundleFiles failed: %v", err)
	}

	poolJSONBytes, err := os.ReadFile(poolPath)
	if err != nil {
		t.Fatalf("reading wg_pool.json: %v", err)
	}
	poolJSON := string(poolJSONBytes)

	// Extract server private key from wg0.conf and assert it NEVER appears in wg_pool.json.
	var serverPrivB64 string
	for _, line := range strings.Split(bundle.ServerConfig, "\n") {
		if strings.HasPrefix(line, "PrivateKey = ") {
			serverPrivB64 = strings.TrimSpace(strings.TrimPrefix(line, "PrivateKey = "))
			break
		}
	}
	if serverPrivB64 == "" {
		t.Fatalf("wg0.conf missing server PrivateKey")
	}
	if strings.Contains(poolJSON, serverPrivB64) {
		t.Fatalf("SECURITY VIOLATION: wg_pool.json leaked ludus-edge ServerPrivateKey")
	}
	if strings.Contains(bundle.ServerConfig, bundle.ClientPool.ClientPoolSeed) {
		t.Fatalf("SECURITY VIOLATION: wg0.conf leaked Ludus ClientPoolSeed")
	}
	if strings.Contains(bundle.ServerConfig, "AllowedIPs = 198.51.100.1/32") {
		t.Fatalf("wg0.conf must reserve 198.51.100.1/24 for server interface, not a client peer")
	}

	loadedPool, err := LoadWireGuardClientPool(poolPath)
	if err != nil {
		t.Fatalf("LoadWireGuardClientPool failed: %v", err)
	}

	// Verify slot bounds enforcement (slot 1 and slot 251 must fail).
	if _, err := loadedPool.DeriveClientPrivateKey(1); err == nil {
		t.Fatalf("expected slot 1 (server reserved) to fail client derivation")
	}
	if _, err := loadedPool.DeriveClientPrivateKey(251); err == nil {
		t.Fatalf("expected slot 251 (> MaxSlot 250) to fail client derivation")
	}

	// Verify deterministic X25519 derivation and exact public-key match in wg0.conf across representative slots.
	for _, slot := range []int{2, 3, 42, 150, 250} {
		priv1, err := loadedPool.DeriveClientPrivateKey(slot)
		if err != nil {
			t.Fatalf("DeriveClientPrivateKey(%d) failed: %v", slot, err)
		}
		priv2, err := loadedPool.DeriveClientPrivateKey(slot)
		if err != nil || priv1 != priv2 {
			t.Fatalf("DeriveClientPrivateKey(%d) was non-deterministic", slot)
		}
		if strings.Contains(bundle.ServerConfig, priv1) {
			t.Fatalf("SECURITY VIOLATION: wg0.conf leaked client private key for slot %d", slot)
		}

		privRaw, err := base64.StdEncoding.DecodeString(priv1)
		if err != nil || len(privRaw) != 32 {
			t.Fatalf("slot %d private key is not 32-byte base64: %v", slot, err)
		}
		// Verify RFC 7748 clamping invariants.
		if privRaw[0]&7 != 0 || privRaw[31]&128 != 0 || privRaw[31]&64 == 0 {
			t.Fatalf("slot %d private key is not RFC 7748 clamped", slot)
		}

		pubRaw, err := curve25519.X25519(privRaw, curve25519.Basepoint)
		if err != nil {
			t.Fatalf("computing public key for slot %d: %v", slot, err)
		}
		pubB64 := base64.StdEncoding.EncodeToString(pubRaw)
		expectedPeerBlock := fmt.Sprintf("[Peer]\nPublicKey = %s\nAllowedIPs = 198.51.100.%d/32", pubB64, slot)
		if !strings.Contains(bundle.ServerConfig, expectedPeerBlock) {
			t.Fatalf("wg0.conf missing matching [Peer] stanza for slot %d:\nwant:\n%s", slot, expectedPeerBlock)
		}
	}
}

func TestResolveWireGuardKeyMaterialAndMonotonicSlots(t *testing.T) {
	origCfg := ServerConfiguration
	defer func() {
		ServerConfiguration = origCfg
	}()

	tmpDir := t.TempDir()
	edgeDir := filepath.Join(tmpDir, "db", "edge")
	poolPath := filepath.Join(edgeDir, "wg_pool.json")

	bundle, err := GenerateEdgeWireGuardBundle("10.0.20.181:51820", 51820, 250)
	if err != nil {
		t.Fatalf("GenerateEdgeWireGuardBundle failed: %v", err)
	}
	if err := WriteWireGuardBundleFiles("", poolPath, bundle); err != nil {
		t.Fatalf("WriteWireGuardBundleFiles failed: %v", err)
	}

	ServerConfiguration = Configuration{
		ContainerMode:     true,
		EdgeAutoProvision: true,
		EdgeStateDir:      edgeDir,
		EdgeVMIP:          "10.0.20.181",
		WireguardPort:     51820,
	}
	ServerConfiguration.ApplyRemoteProxmoxDefaults()

	collection := core.NewAuthCollection("users")
	collection.Fields.Add(
		&core.TextField{Name: "userID"},
		&core.NumberField{Name: "userNumber"},
	)
	rec := core.NewRecord(collection)
	rec.Set("userID", "CS")
	rec.Set("userNumber", 2)
	user := &models.User{}
	user.SetProxyRecord(rec)

	priv, serverPub, endpoint, err := resolveWireGuardKeyMaterialForUser(user)
	if err != nil {
		t.Fatalf("resolveWireGuardKeyMaterialForUser failed: %v", err)
	}
	if priv == "" || serverPub != bundle.ClientPool.ServerPublicKey {
		t.Fatalf("unexpected key material resolved from pool")
	}
	if endpoint != "10.0.20.181:51820" {
		t.Fatalf("expected endpoint 10.0.20.181:51820, got %q", endpoint)
	}

	// Verify monotonic user slot allocation never recycles deleted user slots.
	slotA := AllocateMonotonicWireGuardUserSlot([]int{1})
	if slotA != 2 {
		t.Fatalf("expected first allocated slot 2, got %d", slotA)
	}
	slotB := AllocateMonotonicWireGuardUserSlot([]int{1, 2})
	if slotB != 3 {
		t.Fatalf("expected second allocated slot 3, got %d", slotB)
	}
	// Simulate deleting user 2 (existing DB only has [1, 3]) -> next slot must be 4, never recycling 2!
	slotC := AllocateMonotonicWireGuardUserSlot([]int{1, 3})
	if slotC != 4 {
		t.Fatalf("expected monotonic slot 4 after deleting user 2, got %d", slotC)
	}
}
