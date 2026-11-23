package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseRemoteNodeStorage(t *testing.T) {
	payload := []byte(`[
		{"storage":"local","type":"dir","content":"iso,vztmpl,backup","active":1,"enabled":1,"avail":107374182400},
		{"storage":"local-zfs","type":"zfspool","content":"images,rootdir","active":1,"enabled":1,"avail":536870912000},
		{"storage":"offline-nfs","type":"nfs","content":"images,iso","active":0,"enabled":1,"avail":0}
	]`)

	stores, err := parseRemoteNodeStorage(payload)
	if err != nil {
		t.Fatalf("parseRemoteNodeStorage failed: %v", err)
	}
	if len(stores) != 2 {
		t.Fatalf("expected 2 active datastores, got %d", len(stores))
	}
	if stores[0].Name != "local" || stores[0].AvailKB != 104857600 {
		t.Fatalf("unexpected local store: %+v", stores[0])
	}
	if stores[1].Name != "local-zfs" || formatForPoolType(stores[1].Type) != "raw" {
		t.Fatalf("unexpected local-zfs store: %+v", stores[1])
	}
}

func TestPreStagedBinaryExtractsEmbeddedAssets(t *testing.T) {
	tmp := t.TempDir()
	prevInstallPath := ludusInstallPath
	ludusInstallPath = tmp
	t.Cleanup(func() { ludusInstallPath = prevInstallPath })

	if err := os.WriteFile(filepath.Join(tmp, "ludus-server"), []byte("stub-binary"), 0755); err != nil {
		t.Fatalf("write stub ludus-server: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "config.yml"), []byte("remote_proxmox: true\n"), 0600); err != nil {
		t.Fatalf("write config.yml: %v", err)
	}

	checkDirAndReplaceFiles()

	if _, err := os.Stat(filepath.Join(tmp, "ansible", "requirements.yml")); err != nil {
		t.Fatalf("expected ansible/requirements.yml to be extracted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "ansible", "proxmox-install", "remote-proxmox-vm.yml")); err != nil {
		t.Fatalf("expected remote-proxmox-vm.yml to be extracted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "config.yml")); err != nil {
		t.Fatalf("expected pre-staged config.yml to be preserved: %v", err)
	}
}

