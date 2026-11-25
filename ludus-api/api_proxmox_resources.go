package ludusapi

import (
	"context"
	"fmt"
	"ludusapi/models"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pocketbase/pocketbase/core"
)

var safeProxmoxNodePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// ProxmoxHostNodeResource is the sanitized Proxmox node CPU/memory/load record
// returned by GET /api/v2/proxmox/host-resources for SSH-free LUX container mode.
type ProxmoxHostNodeResource struct {
	Type    string   `json:"type"`
	Node    string   `json:"node"`
	Status  string   `json:"status"`
	CPU     float64  `json:"cpu"`
	MaxCPU  int      `json:"maxcpu"`
	Mem     int64    `json:"mem"`
	MaxMem  int64    `json:"maxmem"`
	Uptime  int64    `json:"uptime,omitempty"`
	LoadAvg []string `json:"loadavg,omitempty"`
}

// ProxmoxTemplateGuest is a sanitized QEMU template/SHARED-pool guest entry
// returned by GET /api/v2/proxmox/template-guests for SSH-free LUX container mode.
type ProxmoxTemplateGuest struct {
	Type     string `json:"type"`
	VMID     int    `json:"vmid"`
	Name     string `json:"name"`
	Node     string `json:"node"`
	Status   string `json:"status,omitempty"`
	Template int    `json:"template"`
}

// ProxmoxSharedAdminVM describes a QEMU VM in Proxmox's ADMIN pool.
type ProxmoxSharedAdminVM struct {
	VMID        int    `json:"vmid"`
	Name        string `json:"name"`
	Node        string `json:"node"`
	Status      string `json:"status"`
	IP          string `json:"ip"`
	ServiceType string `json:"serviceType"`
}

type proxmoxClusterNodeRow struct {
	Type   string  `json:"type"`
	Node   string  `json:"node"`
	Status string  `json:"status"`
	CPU    float64 `json:"cpu"`
	MaxCPU int     `json:"maxcpu"`
	Mem    int64   `json:"mem"`
	MaxMem int64   `json:"maxmem"`
	Uptime int64   `json:"uptime"`
}

type proxmoxClusterVMRow struct {
	Type     string `json:"type"`
	VMID     int    `json:"vmid"`
	Name     string `json:"name"`
	Node     string `json:"node"`
	Pool     string `json:"pool"`
	Status   string `json:"status"`
	Template int    `json:"template"`
}

func newProxmoxRESTClientForRequest(e *core.RequestEvent) (*models.User, *ProxmoxRESTClient, Configuration, error) {
	rawUser := e.Get("user")
	user, ok := rawUser.(*models.User)
	if !ok || user == nil {
		return nil, nil, Configuration{}, fmt.Errorf("authenticated user context is missing")
	}
	if user.Name() == "ROOT" {
		return nil, nil, Configuration{}, fmt.Errorf("ROOT user should not be used for Proxmox resource queries")
	}

	ConfigMu.RLock()
	cfg := ServerConfiguration
	ConfigMu.RUnlock()

	_, tokenID, tokenSecret, err := ResolveProxmoxCredentialsForUser(user)
	if err != nil {
		return nil, nil, Configuration{}, err
	}
	client := NewProxmoxAPITokenClient(cfg.ProxmoxURL, cfg.ProxmoxInvalidCert, tokenID, tokenSecret)
	return user, client, cfg, nil
}

func filterProxmoxHostNodes(rows []proxmoxClusterNodeRow, cfg Configuration) []ProxmoxHostNodeResource {
	pinnedNode := ""
	if cfg.ProxmoxPinToNode {
		pinnedNode = strings.TrimSpace(cfg.ProxmoxNode)
	}

	candidates := make([]ProxmoxHostNodeResource, 0, len(rows))
	hasAccessibleMetrics := false
	for _, r := range rows {
		if r.Type != "" && r.Type != "node" {
			continue
		}
		nodeName := strings.TrimSpace(r.Node)
		if nodeName == "" || !safeProxmoxNodePattern.MatchString(nodeName) {
			continue
		}
		if pinnedNode != "" && !strings.EqualFold(nodeName, pinnedNode) {
			continue
		}
		if r.MaxMem > 0 || r.MaxCPU > 0 {
			hasAccessibleMetrics = true
		}
		candidates = append(candidates, ProxmoxHostNodeResource{
			Type:   "node",
			Node:   nodeName,
			Status: r.Status,
			CPU:    r.CPU,
			MaxCPU: r.MaxCPU,
			Mem:    r.Mem,
			MaxMem: r.MaxMem,
			Uptime: r.Uptime,
		})
	}

	// On multi-node clusters where ludus-svc has NoAccess on sibling nodes,
	// Proxmox still lists those sibling nodes with maxcpu=0, maxmem=0, status="unknown".
	// Exclude zero-capacity placeholder entries whenever at least one real node is visible.
	if hasAccessibleMetrics {
		filtered := candidates[:0]
		for _, n := range candidates {
			if n.MaxMem > 0 || n.MaxCPU > 0 {
				filtered = append(filtered, n)
			}
		}
		candidates = filtered
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Node < candidates[j].Node
	})
	return candidates
}

// GetProxmoxHostResources returns sanitized Proxmox host CPU/memory/load metrics
// over REST so LUX in SSH-free container mode never requires Proxmox SSH.
func GetProxmoxHostResources(e *core.RequestEvent) error {
	_, client, cfg, err := newProxmoxRESTClientForRequest(e)
	if err != nil {
		return JSONError(e, http.StatusForbidden, err.Error())
	}

	ctx, cancel := context.WithTimeout(e.Request.Context(), 12*time.Second)
	defer cancel()

	var rows []proxmoxClusterNodeRow
	if err := client.Do(ctx, http.MethodGet, "/cluster/resources", url.Values{"type": {"node"}}, &rows); err != nil {
		return JSONError(e, http.StatusBadGateway, fmt.Sprintf("Failed to read Proxmox node resources: %v", err))
	}

	nodes := filterProxmoxHostNodes(rows, cfg)
	for i := range nodes {
		statusCtx, statusCancel := context.WithTimeout(ctx, 4*time.Second)
		var st struct {
			LoadAvg []string `json:"loadavg"`
		}
		if err := client.Do(statusCtx, http.MethodGet, "/nodes/"+url.PathEscape(nodes[i].Node)+"/status", nil, &st); err == nil && len(st.LoadAvg) > 0 {
			nodes[i].LoadAvg = st.LoadAvg
		}
		statusCancel()
	}

	return e.JSON(http.StatusOK, nodes)
}

func filterProxmoxTemplateGuests(rows []proxmoxClusterVMRow, cfg Configuration) []ProxmoxTemplateGuest {
	pinnedNode := ""
	if cfg.ProxmoxPinToNode {
		pinnedNode = strings.TrimSpace(cfg.ProxmoxNode)
	}

	out := make([]ProxmoxTemplateGuest, 0, len(rows))
	for _, r := range rows {
		if r.Type != "" && r.Type != "qemu" {
			continue
		}
		if r.VMID <= 0 || strings.TrimSpace(r.Name) == "" {
			continue
		}
		// Only expose VM templates or SHARED-pool guests — never other tenants' range VMs.
		if r.Template != 1 && !strings.EqualFold(strings.TrimSpace(r.Pool), "SHARED") {
			continue
		}
		if pinnedNode != "" && r.Node != "" && !strings.EqualFold(r.Node, pinnedNode) {
			continue
		}
		tpl := 0
		if r.Template == 1 {
			tpl = 1
		}
		out = append(out, ProxmoxTemplateGuest{
			Type:     "qemu",
			VMID:     r.VMID,
			Name:     strings.TrimSpace(r.Name),
			Node:     strings.TrimSpace(r.Node),
			Status:   r.Status,
			Template: tpl,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].VMID < out[j].VMID
	})
	return out
}

// GetProxmoxTemplateGuests returns QEMU template guests visible to Ludus so LUX's
// Templates view works in SSH-free container mode without exposing tenant VMs.
func GetProxmoxTemplateGuests(e *core.RequestEvent) error {
	_, client, cfg, err := newProxmoxRESTClientForRequest(e)
	if err != nil {
		return JSONError(e, http.StatusForbidden, err.Error())
	}

	ctx, cancel := context.WithTimeout(e.Request.Context(), 12*time.Second)
	defer cancel()

	var rows []proxmoxClusterVMRow
	if err := client.Do(ctx, http.MethodGet, "/cluster/resources", url.Values{"type": {"vm"}}, &rows); err != nil {
		return JSONError(e, http.StatusBadGateway, fmt.Sprintf("Failed to read Proxmox template guests: %v", err))
	}

	return e.JSON(http.StatusOK, filterProxmoxTemplateGuests(rows, cfg))
}

func classifySharedAdminServiceType(name string) string {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "nexus") {
		return "nexus"
	}
	if lower == "share" || strings.HasPrefix(lower, "share-") || strings.HasSuffix(lower, "-share") || strings.Contains(lower, "-share-") || strings.Contains(lower, "ludus-share") || strings.Contains(lower, "ludusshare") {
		return "share"
	}
	return "other"
}

// GetProxmoxSharedAdminVMs returns QEMU VMs in Proxmox's ADMIN pool for LUX admins.
func GetProxmoxSharedAdminVMs(e *core.RequestEvent) error {
	user, client, cfg, err := newProxmoxRESTClientForRequest(e)
	if err != nil {
		return JSONError(e, http.StatusForbidden, err.Error())
	}
	if !user.IsAdmin() {
		return JSONError(e, http.StatusForbidden, "Admin privileges required")
	}

	ctx, cancel := context.WithTimeout(e.Request.Context(), 15*time.Second)
	defer cancel()

	var pool struct {
		Members []struct {
			VMID int    `json:"vmid"`
			Node string `json:"node"`
			Type string `json:"type"`
			Name string `json:"name"`
		} `json:"members"`
	}
	if err := client.Do(ctx, http.MethodGet, "/pools/ADMIN", nil, &pool); err != nil {
		errLower := strings.ToLower(err.Error())
		if strings.Contains(errLower, "does not exist") || strings.Contains(errLower, "not found") || strings.Contains(errLower, "status 404") {
			return e.JSON(http.StatusOK, map[string]any{"vms": []ProxmoxSharedAdminVM{}})
		}
		return JSONError(e, http.StatusBadGateway, fmt.Sprintf("Failed to query Proxmox ADMIN pool: %v", err))
	}

	fallbackNode := strings.TrimSpace(cfg.ProxmoxNode)
	if fallbackNode == "" {
		fallbackNode = "pve"
	}

	vms := make([]ProxmoxSharedAdminVM, 0, len(pool.Members))
	for _, m := range pool.Members {
		if m.Type != "" && m.Type != "qemu" {
			continue
		}
		if m.VMID <= 0 {
			continue
		}
		node := strings.TrimSpace(m.Node)
		if node == "" {
			node = fallbackNode
		}
		if cfg.ProxmoxPinToNode && strings.TrimSpace(cfg.ProxmoxNode) != "" && !strings.EqualFold(node, strings.TrimSpace(cfg.ProxmoxNode)) {
			continue
		}

		name := strings.TrimSpace(m.Name)
		if name == "" {
			name = fmt.Sprintf("vmid-%d", m.VMID)
		}
		status := "unknown"
		ip := ""

		var st struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		}
		vmPrefix := fmt.Sprintf("/nodes/%s/qemu/%d", url.PathEscape(node), m.VMID)
		if err := client.Do(ctx, http.MethodGet, vmPrefix+"/status/current", nil, &st); err == nil {
			if strings.TrimSpace(st.Name) != "" {
				name = strings.TrimSpace(st.Name)
			}
			switch st.Status {
			case "running", "stopped":
				status = st.Status
			}
		}

		if status == "running" {
			gaCtx, gaCancel := context.WithTimeout(ctx, 3*time.Second)
			var ga struct {
				Result []struct {
					IPAddresses []struct {
						IPAddress     string `json:"ip-address"`
						IPAddressType string `json:"ip-address-type"`
					} `json:"ip-addresses"`
				} `json:"result"`
			}
			if err := client.Do(gaCtx, http.MethodGet, vmPrefix+"/agent/network-get-interfaces", nil, &ga); err == nil {
				for _, iface := range ga.Result {
					for _, addr := range iface.IPAddresses {
						a := strings.TrimSpace(addr.IPAddress)
						if addr.IPAddressType == "ipv4" && a != "" && !strings.HasPrefix(a, "127.") && !strings.HasPrefix(a, "169.254.") {
							ip = a
							break
						}
					}
					if ip != "" {
						break
					}
				}
			}
			gaCancel()
		}

		vms = append(vms, ProxmoxSharedAdminVM{
			VMID:        m.VMID,
			Name:        name,
			Node:        node,
			Status:      status,
			IP:          ip,
			ServiceType: classifySharedAdminServiceType(name),
		})
	}

	return e.JSON(http.StatusOK, map[string]any{"vms": vms})
}

// PutProxmoxSharedAdminVMPower starts or stops a VM strictly verified to belong to Proxmox's ADMIN pool.
func PutProxmoxSharedAdminVMPower(e *core.RequestEvent) error {
	user, client, cfg, err := newProxmoxRESTClientForRequest(e)
	if err != nil {
		return JSONError(e, http.StatusForbidden, err.Error())
	}
	if !user.IsAdmin() {
		return JSONError(e, http.StatusForbidden, "Admin privileges required")
	}

	vmidStr := strings.TrimSpace(e.Request.PathValue("vmid"))
	vmid, convErr := strconv.Atoi(vmidStr)
	if convErr != nil || vmid <= 0 {
		return JSONError(e, http.StatusBadRequest, "Valid vmid required")
	}
	action := strings.TrimSpace(e.Request.URL.Query().Get("action"))
	if action != "start" && action != "stop" {
		return JSONError(e, http.StatusBadRequest, "action must be 'start' or 'stop'")
	}

	ctx, cancel := context.WithTimeout(e.Request.Context(), 15*time.Second)
	defer cancel()

	var pool struct {
		Members []struct {
			VMID int    `json:"vmid"`
			Node string `json:"node"`
			Type string `json:"type"`
		} `json:"members"`
	}
	if err := client.Do(ctx, http.MethodGet, "/pools/ADMIN", nil, &pool); err != nil {
		return JSONError(e, http.StatusBadGateway, fmt.Sprintf("Failed to verify ADMIN pool membership: %v", err))
	}

	targetNode := ""
	for _, m := range pool.Members {
		if m.VMID == vmid && (m.Type == "" || m.Type == "qemu") {
			targetNode = strings.TrimSpace(m.Node)
			if targetNode == "" {
				targetNode = strings.TrimSpace(cfg.ProxmoxNode)
			}
			break
		}
	}
	if targetNode == "" {
		return JSONError(e, http.StatusForbidden, fmt.Sprintf("VM %d is not in the ADMIN pool", vmid))
	}
	if cfg.ProxmoxPinToNode && strings.TrimSpace(cfg.ProxmoxNode) != "" && !strings.EqualFold(targetNode, strings.TrimSpace(cfg.ProxmoxNode)) {
		return JSONError(e, http.StatusForbidden, fmt.Sprintf("VM %d is not on pinned node %s", vmid, cfg.ProxmoxNode))
	}

	apiPath := fmt.Sprintf("/nodes/%s/qemu/%d/status/%s", url.PathEscape(targetNode), vmid, action)
	if err := client.Do(ctx, http.MethodPost, apiPath, nil, nil); err != nil {
		return JSONError(e, http.StatusBadGateway, fmt.Sprintf("Failed to %s ADMIN VM %d: %v", action, vmid, err))
	}
	return e.JSON(http.StatusOK, map[string]any{"ok": true})
}
