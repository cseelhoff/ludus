package ludusapi

import "testing"

func TestFilterProxmoxHostNodesPinsAndDropsZeroCapacitySiblings(t *testing.T) {
	rows := []proxmoxClusterNodeRow{
		{Type: "node", Node: "pve-prod-01", Status: "unknown", CPU: 0, MaxCPU: 0, Mem: 0, MaxMem: 0},
		{Type: "node", Node: "pve-prod-02", Status: "online", CPU: 0.125, MaxCPU: 64, Mem: 34359738368, MaxMem: 137438953472, Uptime: 86400},
		{Type: "node", Node: "pve-prod-03", Status: "online", CPU: 0.25, MaxCPU: 32, Mem: 17179869184, MaxMem: 68719476736, Uptime: 43200},
	}

	pinned := filterProxmoxHostNodes(rows, Configuration{
		ProxmoxPinToNode: true,
		ProxmoxNode:      "pve-prod-02",
	})
	if len(pinned) != 1 || pinned[0].Node != "pve-prod-02" {
		t.Fatalf("expected only pinned node pve-prod-02, got %+v", pinned)
	}

	unpinned := filterProxmoxHostNodes(rows, Configuration{
		ProxmoxPinToNode: false,
	})
	if len(unpinned) != 2 || unpinned[0].Node != "pve-prod-02" || unpinned[1].Node != "pve-prod-03" {
		t.Fatalf("expected zero-capacity NoAccess sibling to be dropped, got %+v", unpinned)
	}
}

func TestFilterProxmoxTemplateGuestsExcludesTenantRangeVMs(t *testing.T) {
	rows := []proxmoxClusterVMRow{
		{Type: "qemu", VMID: 9001, Name: "win11-22h2-x64-enterprise-template", Node: "pve-prod-02", Pool: "SHARED", Template: 1},
		{Type: "qemu", VMID: 201, Name: "CA-ad-dc-win2022-server-x64", Node: "pve-prod-02", Pool: "CA", Template: 0},
		{Type: "qemu", VMID: 9002, Name: "debian-12-x64-server-template", Node: "pve-prod-03", Pool: "SHARED", Template: 1},
	}

	guests := filterProxmoxTemplateGuests(rows, Configuration{
		ProxmoxPinToNode: true,
		ProxmoxNode:      "pve-prod-02",
	})
	if len(guests) != 1 || guests[0].VMID != 9001 || guests[0].Template != 1 {
		t.Fatalf("expected only pinned template 9001, got %+v", guests)
	}
}
