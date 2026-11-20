package main

import (
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
