package ludusapi

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// VerifyProxmoxServiceToken validates a least-privilege Proxmox service API token
// over HTTPS (:8006) and idempotently ensures Ludus resource pools (SHARED, ADMIN)
// and the SDN zone + ludusnat VNet without touching /access/roles, /access/groups,
// /access/users, /access/password, or /access/acl.
func VerifyProxmoxServiceToken(ctx context.Context, cfg *Configuration) error {
	if cfg == nil {
		cfg = &ServerConfiguration
	}
	cfg.ApplyRemoteProxmoxDefaults()

	tokenID, tokenSecret, ok, err := ResolveProxmoxServiceToken(cfg)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("proxmox_auth_mode is service_token, but proxmox_api_token_id / proxmox_api_token_file is not configured")
	}

	client := NewProxmoxAPITokenClient(cfg.ProxmoxURL, cfg.ProxmoxInvalidCert, tokenID, tokenSecret)

	var ver struct {
		Version string `json:"version"`
		Release string `json:"release"`
	}
	if err := client.Do(ctx, http.MethodGet, "/version", nil, &ver); err != nil {
		return fmt.Errorf("querying remote Proxmox /version with service token %s: %w", tokenID, err)
	}
	verStr := ver.Version
	if verStr == "" {
		verStr = ver.Release
	}
	if !strings.HasPrefix(verStr, "8.") && !strings.HasPrefix(verStr, "9.") && verStr != "8" && verStr != "9" {
		return fmt.Errorf("unsupported remote Proxmox VE version %q (Ludus requires Proxmox VE 8 or 9)", verStr)
	}

	var nodes []struct {
		Node string `json:"node"`
	}
	if err := client.Do(ctx, http.MethodGet, "/nodes", nil, &nodes); err != nil {
		return fmt.Errorf("listing Proxmox nodes with service token %s: %w", tokenID, err)
	}
	var nodeNames []string
	for _, n := range nodes {
		if n.Node != "" {
			nodeNames = append(nodeNames, n.Node)
		}
	}
	if targetNode := strings.TrimSpace(cfg.ProxmoxNode); targetNode != "" && len(nodeNames) > 0 && !containsString(nodeNames, targetNode) {
		return fmt.Errorf("configured proxmox_node %q not visible to service token %s (visible nodes: %v)", targetNode, tokenID, nodeNames)
	}

	requiredPools := []struct {
		PoolID  string
		Comment string
	}{
		{PoolID: "SHARED", Comment: "Templates shared with all Ludus users"},
		{PoolID: "ADMIN", Comment: "VMs managed by the Ludus admin"},
	}
	for _, pool := range requiredPools {
		if err := ensureProxmoxPoolREST(ctx, client, pool.PoolID, pool.Comment); err != nil {
			return err
		}
	}

	clusterMode := len(nodes) > 1 || cfg.ClusterMode
	zoneName := cfg.SDNZone
	if zoneName == "" {
		zoneName = "ludus"
	}
	natVNet := cfg.EffectiveLudusNATInterface()
	if err := ensureSDNZoneAndNATVNetREST(ctx, client, zoneName, natVNet, cfg.VXLANTagBase, clusterMode); err != nil {
		return err
	}

	return nil
}

// BootstrapRemoteProxmox idempotently configures a remote Proxmox VE 8/9 standalone host
// or cluster over HTTPS (:8006) with all roles, groups, resource pools, SDN zone/VNet,
// and ACLs required by Ludus — replacing local lae.proxmox / pveum / pvesh execution.
// When proxmox_auth_mode is "service_token", it delegates to VerifyProxmoxServiceToken.
func BootstrapRemoteProxmox(ctx context.Context, cfg *Configuration) error {
	if cfg == nil {
		cfg = &ServerConfiguration
	}
	cfg.ApplyRemoteProxmoxDefaults()
	if cfg.IsServiceTokenAuthMode() {
		return VerifyProxmoxServiceToken(ctx, cfg)
	}

	client, err := NewProxmoxBestEffortAdminClient(ctx, cfg)
	if err != nil {
		return fmt.Errorf("connecting to remote Proxmox for bootstrap: %w", err)
	}

	// 1. Verify Proxmox VE 8 or 9
	var ver struct {
		Version string `json:"version"`
		Release string `json:"release"`
	}
	if err := client.Do(ctx, http.MethodGet, "/version", nil, &ver); err != nil {
		return fmt.Errorf("querying remote Proxmox /version: %w", err)
	}
	verStr := ver.Version
	if verStr == "" {
		verStr = ver.Release
	}
	if !strings.HasPrefix(verStr, "8.") && !strings.HasPrefix(verStr, "9.") && verStr != "8" && verStr != "9" {
		return fmt.Errorf("unsupported remote Proxmox VE version %q (Ludus requires Proxmox VE 8 or 9)", verStr)
	}

	// 2. Ensure custom roles (ResourceAudit, DatastoreUser, AccessNetwork)
	requiredRoles := []struct {
		RoleID string
		Privs  string
	}{
		{RoleID: "ResourceAudit", Privs: "Sys.Audit,Datastore.Audit"},
		{RoleID: "DatastoreUser", Privs: "Datastore.AllocateSpace,Datastore.AllocateTemplate,Datastore.Audit"},
		{RoleID: "AccessNetwork", Privs: "Sys.AccessNetwork"},
	}
	for _, role := range requiredRoles {
		if err := ensureProxmoxRoleREST(ctx, client, role.RoleID, role.Privs); err != nil {
			return err
		}
	}

	// 3. Ensure Ludus groups (ludus_users, ludus_admins)
	requiredGroups := []struct {
		GroupID string
		Comment string
	}{
		{GroupID: "ludus_users", Comment: "Ludus users"},
		{GroupID: "ludus_admins", Comment: "Ludus admins"},
	}
	for _, grp := range requiredGroups {
		if err := ensureProxmoxGroupREST(ctx, client, grp.GroupID, grp.Comment); err != nil {
			return err
		}
	}

	// 4. Ensure Ludus resource pools (SHARED, ADMIN)
	requiredPools := []struct {
		PoolID  string
		Comment string
	}{
		{PoolID: "SHARED", Comment: "Templates shared with all Ludus users"},
		{PoolID: "ADMIN", Comment: "VMs managed by the Ludus admin"},
	}
	for _, pool := range requiredPools {
		if err := ensureProxmoxPoolREST(ctx, client, pool.PoolID, pool.Comment); err != nil {
			return err
		}
	}

	// 5. Discover Proxmox nodes for node-level ACLs and standalone-vs-cluster SDN handling
	var nodes []struct {
		Node string `json:"node"`
	}
	if err := client.Do(ctx, http.MethodGet, "/nodes", nil, &nodes); err != nil {
		return fmt.Errorf("listing Proxmox nodes: %w", err)
	}
	var nodeNames []string
	for _, n := range nodes {
		if n.Node != "" {
			nodeNames = append(nodeNames, n.Node)
		}
	}
	if cfg.ProxmoxNode != "" && !containsString(nodeNames, cfg.ProxmoxNode) {
		nodeNames = append(nodeNames, cfg.ProxmoxNode)
	}

	clusterMode := len(nodes) > 1
	if cfg.ClusterMode {
		clusterMode = true
	}

	// 6. Ensure SDN zone and ludusnat VNet via Proxmox SDN REST API
	zoneName := cfg.SDNZone
	if zoneName == "" {
		zoneName = "ludus"
	}
	natVNet := cfg.EffectiveLudusNATInterface()
	if err := ensureSDNZoneAndNATVNetREST(ctx, client, zoneName, natVNet, cfg.VXLANTagBase, clusterMode); err != nil {
		return err
	}

	// 7. Apply group ACLs across pools, root, nodes, datastores, and SDN VNets
	type groupACLSpec struct {
		Path   string
		Group  string
		Roles  string
		Strict bool
	}
	acls := []groupACLSpec{
		{Path: "/pool/SHARED", Group: "ludus_users", Roles: "PVEVMAdmin,PVEPoolUser,PVESDNAdmin", Strict: true},
		{Path: "/pool/ADMIN", Group: "ludus_admins", Roles: "PVEVMAdmin,PVESDNAdmin,PVEPoolAdmin", Strict: true},
		{Path: "/pool", Group: "ludus_users", Roles: "PVEPoolAdmin", Strict: true},
		{Path: "/", Group: "ludus_users", Roles: "ResourceAudit", Strict: true},
		{Path: fmt.Sprintf("/sdn/zones/%s/%s", zoneName, natVNet), Group: "ludus_users", Roles: "PVESDNUser", Strict: true},
		{Path: "/sdn/zones/localnetwork", Group: "ludus_users", Roles: "PVESDNUser", Strict: false},
	}

	for _, node := range nodeNames {
		if !cfg.IsProxmoxNodeAllowed(node) {
			continue
		}
		acls = append(acls,
			groupACLSpec{Path: "/nodes/" + node, Group: "ludus_users", Roles: "ResourceAudit", Strict: true},
			groupACLSpec{Path: "/nodes/" + node, Group: "ludus_users", Roles: "AccessNetwork", Strict: true},
		)
	}

	for _, storage := range uniqueNonEmptyStrings(cfg.ProxmoxVMStoragePool, cfg.ProxmoxISOStoragePool) {
		acls = append(acls,
			groupACLSpec{Path: "/storage/" + storage, Group: "ludus_admins", Roles: "PVEDatastoreAdmin", Strict: true},
			groupACLSpec{Path: "/storage/" + storage, Group: "ludus_users", Roles: "DatastoreUser", Strict: true},
		)
	}

	for _, spec := range acls {
		for _, role := range strings.Split(spec.Roles, ",") {
			err := putProxmoxACL(ctx, client, spec.Path, "", spec.Group, strings.TrimSpace(role))
			if err != nil && spec.Strict {
				return err
			}
		}
	}

	return nil
}

func ensureProxmoxRoleREST(ctx context.Context, client *ProxmoxRESTClient, roleID, privs string) error {
	rolePath := "/access/roles/" + url.PathEscape(roleID)
	var existing interface{}
	if err := client.Do(ctx, http.MethodGet, rolePath, nil, &existing); err != nil {
		form := url.Values{}
		form.Set("roleid", roleID)
		form.Set("privs", privs)
		if postErr := client.Do(ctx, http.MethodPost, "/access/roles", form, nil); postErr != nil {
			return fmt.Errorf("creating Proxmox role %s: %w", roleID, postErr)
		}
		return nil
	}
	form := url.Values{}
	form.Set("privs", privs)
	if err := client.Do(ctx, http.MethodPut, rolePath, form, nil); err != nil {
		return fmt.Errorf("updating Proxmox role %s: %w", roleID, err)
	}
	return nil
}

func ensureProxmoxGroupREST(ctx context.Context, client *ProxmoxRESTClient, groupID, comment string) error {
	groupPath := "/access/groups/" + url.PathEscape(groupID)
	var existing interface{}
	if err := client.Do(ctx, http.MethodGet, groupPath, nil, &existing); err == nil {
		return nil
	}
	form := url.Values{}
	form.Set("groupid", groupID)
	if comment != "" {
		form.Set("comment", comment)
	}
	if err := client.Do(ctx, http.MethodPost, "/access/groups", form, nil); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "already exists") {
			return nil
		}
		return fmt.Errorf("creating Proxmox group %s: %w", groupID, err)
	}
	return nil
}

func ensureProxmoxPoolREST(ctx context.Context, client *ProxmoxRESTClient, poolID, comment string) error {
	var pools []struct {
		PoolID string `json:"poolid"`
	}
	if err := client.Do(ctx, http.MethodGet, "/pools", nil, &pools); err == nil {
		for _, p := range pools {
			if p.PoolID == poolID {
				return nil
			}
		}
	}
	form := url.Values{}
	form.Set("poolid", poolID)
	if comment != "" {
		form.Set("comment", comment)
	}
	if err := client.Do(ctx, http.MethodPost, "/pools", form, nil); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "already exists") {
			return nil
		}
		return fmt.Errorf("creating Proxmox pool %s: %w", poolID, err)
	}
	return nil
}

func ensureSDNZoneAndNATVNetREST(ctx context.Context, client *ProxmoxRESTClient, zoneName, natVNet string, vxlanTagBase int, clusterMode bool) error {
	var zones []struct {
		Zone string `json:"zone"`
		Type string `json:"type"`
	}
	if err := client.Do(ctx, http.MethodGet, "/cluster/sdn/zones", nil, &zones); err != nil {
		return fmt.Errorf("listing Proxmox SDN zones: %w", err)
	}

	var zoneType string
	for _, z := range zones {
		if z.Zone == zoneName {
			zoneType = z.Type
			break
		}
	}

	needSDNApply := false
	if zoneType == "" {
		if clusterMode {
			return fmt.Errorf("cluster mode requires a pre-configured SDN zone '%s' on Proxmox with VXLAN peer IPs", zoneName)
		}
		form := url.Values{}
		form.Set("zone", zoneName)
		form.Set("type", SDNZoneTypeSimple)
		if err := client.Do(ctx, http.MethodPost, "/cluster/sdn/zones", form, nil); err != nil {
			return fmt.Errorf("creating standalone Proxmox SDN simple zone %s: %w", zoneName, err)
		}
		zoneType = SDNZoneTypeSimple
		needSDNApply = true
	}

	var vnets []struct {
		VNet string `json:"vnet"`
	}
	if err := client.Do(ctx, http.MethodGet, "/cluster/sdn/vnets", nil, &vnets); err != nil {
		return fmt.Errorf("listing Proxmox SDN VNets: %w", err)
	}

	vnetExists := false
	for _, v := range vnets {
		if v.VNet == natVNet {
			vnetExists = true
			break
		}
	}

	if !vnetExists {
		opts, err := BuildVNetOptionsForZone(natVNet, zoneName, zoneType, true, vxlanTagBase, 0)
		if err != nil {
			return err
		}
		form := url.Values{}
		form.Set("vnet", opts.Name)
		form.Set("zone", opts.Zone)
		if opts.VlanAware {
			form.Set("vlanaware", "1")
		}
		if opts.Tag > 0 {
			form.Set("tag", fmt.Sprintf("%d", opts.Tag))
		}
		if err := client.Do(ctx, http.MethodPost, "/cluster/sdn/vnets", form, nil); err != nil {
			return fmt.Errorf("creating Proxmox SDN NAT VNet %s in zone %s: %w", natVNet, zoneName, err)
		}
		needSDNApply = true
	}

	if needSDNApply {
		var upid string
		if err := client.Do(ctx, http.MethodPut, "/cluster/sdn", nil, &upid); err != nil {
			return fmt.Errorf("applying Proxmox SDN configuration: %w", err)
		}
		if strings.HasPrefix(upid, "UPID:") {
			_ = waitForProxmoxUPID(ctx, client, upid, 60*time.Second)
		}
	}
	return nil
}

func waitForProxmoxUPID(ctx context.Context, client *ProxmoxRESTClient, upid string, timeout time.Duration) error {
	parts := strings.Split(upid, ":")
	if len(parts) < 2 || parts[1] == "" {
		return nil
	}
	node := parts[1]
	statusPath := fmt.Sprintf("/nodes/%s/tasks/%s/status", url.PathEscape(node), url.PathEscape(upid))
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var st struct {
			Status     string `json:"status"`
			ExitStatus string `json:"exitstatus"`
		}
		if err := client.Do(ctx, http.MethodGet, statusPath, nil, &st); err != nil {
			return err
		}
		if st.Status == "stopped" {
			if st.ExitStatus != "" && st.ExitStatus != "OK" {
				return fmt.Errorf("proxmox task %s failed with status %s", upid, st.ExitStatus)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("timed out waiting for Proxmox task %s", upid)
}
