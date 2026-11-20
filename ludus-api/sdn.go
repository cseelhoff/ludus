package ludusapi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	goproxmox "github.com/luthermonson/go-proxmox"
	"github.com/spf13/viper"
)

// SDN Zone types
const (
	SDNZoneTypeSimple = "simple" // For standalone single-node Proxmox (local Linux bridge VNet, no VNI tag)
	SDNZoneTypeVXLAN  = "vxlan"  // For multi-node cluster mode (VXLAN VNI tag)
	SDNZoneTypeEVPN   = "evpn"   // BGP EVPN overlay (VNI tag)
	SDNZoneTypeVLAN   = "vlan"   // 802.1Q VLAN zone (tag 1..4094)
	SDNZoneTypeQinQ   = "qinq"   // 802.1ad QinQ service VLAN zone (tag 1..4094, vlanaware)
	NATVNetName       = "ludusnat"
)

// ShouldUseSDN returns true whenever Proxmox SDN should manage range networks.
// RemoteProxmox VM mode ALWAYS uses SDN (both on single-node standalone Proxmox via
// 'simple'/'vlan'/'qinq' zones and on multi-node clusters via 'vxlan'/'evpn' zones)
// because ludus-server runs inside a guest VM and cannot create vmbr1001+ bridges on
// the hypervisor via local /etc/network/interfaces edits.
func ShouldUseSDN() (bool, error) {
	ConfigMu.RLock()
	remote := ServerConfiguration.RemoteProxmox
	ConfigMu.RUnlock()
	if remote {
		return true, nil
	}
	return IsClusterMode()
}

// IsClusterMode checks if this Proxmox instance is part of a cluster.
// First checks if the user has explicitly set cluster_mode in config.
// If not set, falls back to API detection by checking if there are multiple nodes.
func IsClusterMode() (bool, error) {
	// Check if user has explicitly set cluster_mode in config
	if viper.IsSet("cluster_mode") {
		logger.Debug(fmt.Sprintf("Cluster mode explicitly set in config to: %t", ServerConfiguration.ClusterMode))
		return ServerConfiguration.ClusterMode, nil
	}

	client, err := GetRootGoProxmoxClient()
	if err != nil {
		return false, fmt.Errorf("failed to get proxmox client: %w", err)
	}

	// Fall back to API detection
	ctx := context.Background()
	cluster, err := client.Cluster(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to get cluster client: %w", err)
	}
	// Get cluster status - if we have multiple nodes, we're in cluster mode
	nodes, err := cluster.Resources(ctx, "node")
	if err != nil {
		return false, fmt.Errorf("failed to get cluster resources: %w", err)
	}
	return len(nodes) > 1, nil
}

// GetClusterNodes returns all nodes in the Proxmox cluster as NodeStatuses
func GetClusterNodes(client *goproxmox.Client) (goproxmox.NodeStatuses, error) {
	ctx := context.Background()
	return client.Nodes(ctx)
}

// GetNodeResourceUsage returns CPU and memory usage percentage for a node
// Uses the NodeStatus which already has CPU and Mem info from the nodes list
func GetNodeResourceUsage(client *goproxmox.Client, nodeName string) (cpuPercent float64, memPercent float64, err error) {
	ctx := context.Background()
	nodes, err := client.Nodes(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get nodes: %w", err)
	}

	for _, nodeStatus := range nodes {
		if nodeStatus.Node == nodeName {
			// CPU usage is already a percentage (0-1)
			cpuPercent = nodeStatus.CPU * 100

			// Memory usage as percentage
			if nodeStatus.MaxMem > 0 {
				memPercent = float64(nodeStatus.Mem) / float64(nodeStatus.MaxMem) * 100
			}

			return cpuPercent, memPercent, nil
		}
	}

	return 0, 0, fmt.Errorf("node %s not found", nodeName)
}

// SelectOptimalNode selects the best permitted online node for deployment.
// Uses 80% RAM weight, 20% CPU weight to favor nodes with more available memory,
// while honoring proxmox_pin_to_node / proxmox_allowed_nodes restrictions.
func SelectOptimalNode(client *goproxmox.Client) (string, error) {
	nodes, err := GetClusterNodes(client)
	if err != nil {
		return "", fmt.Errorf("failed to get nodes: %w", err)
	}
	return selectOptimalNodeFromStatuses(nodes, AllowedProxmoxNodes())
}

func selectOptimalNodeFromStatuses(nodes goproxmox.NodeStatuses, allowedNodes []string) (string, error) {
	if len(nodes) == 0 {
		return "", fmt.Errorf("no nodes found in cluster")
	}

	var candidates []*goproxmox.NodeStatus
	for _, nodeStatus := range nodes {
		if nodeStatus == nil {
			continue
		}
		if len(allowedNodes) > 0 && !slices.Contains(allowedNodes, nodeStatus.Node) {
			continue
		}
		candidates = append(candidates, nodeStatus)
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("no cluster nodes match allowed Proxmox nodes %v", allowedNodes)
	}
	if len(candidates) == 1 {
		if candidates[0].Status != "" && candidates[0].Status != "online" {
			return "", fmt.Errorf("pinned Proxmox node %s is not online (status=%s)", candidates[0].Node, candidates[0].Status)
		}
		return candidates[0].Node, nil
	}

	var bestNode string
	var bestScore float64 = 1000.0 // Start with a high score (lower is better)

	for _, nodeStatus := range candidates {
		if nodeStatus.Status != "online" {
			continue
		}

		cpu := nodeStatus.CPU * 100
		var mem float64
		if nodeStatus.MaxMem > 0 {
			mem = float64(nodeStatus.Mem) / float64(nodeStatus.MaxMem) * 100
		}

		// Lower score = better (more available resources)
		// Weight memory more heavily (80%) as VMs typically need more RAM
		score := (mem * 0.8) + (cpu * 0.2)
		logger.Debug(fmt.Sprintf("Node %s: CPU=%.1f%%, MEM=%.1f%%, Score=%.2f", nodeStatus.Node, cpu, mem, score))

		if score < bestScore {
			bestScore = score
			bestNode = nodeStatus.Node
		}
	}

	if bestNode == "" {
		return "", fmt.Errorf("no suitable online node found")
	}

	logger.Debug(fmt.Sprintf("Selected optimal node: %s (score: %.2f)", bestNode, bestScore))
	return bestNode, nil
}

// CreateSimpleSDNZone creates the Ludus SDN zone using go-proxmox library
// Uses "simple" type for standalone
func CreateSimpleSDNZone(client *goproxmox.Client, zoneName string) error {
	ctx := context.Background()
	cluster, err := client.Cluster(ctx)
	if err != nil {
		return fmt.Errorf("failed to get cluster client: %w", err)
	}

	zoneType := SDNZoneTypeSimple

	// Use go-proxmox's SDNZoneOptions struct
	zoneOpts := &goproxmox.SDNZoneOptions{
		Name: zoneName,
		Type: zoneType,
	}

	// Use library's NewSDNZone function
	err = cluster.NewSDNZone(ctx, zoneOpts)
	if err != nil {
		return fmt.Errorf("failed to create SDN zone %s: %w", zoneName, err)
	}

	logger.Debug(fmt.Sprintf("Created SDN zone %s (type: %s)", zoneName, zoneType))
	return nil
}

// CreateVNet creates an SDN VNet using go-proxmox library
func CreateVNet(client *goproxmox.Client, vnetName string, zoneName string, tag uint32) error {
	ctx := context.Background()
	cluster, err := client.Cluster(ctx)
	if err != nil {
		return fmt.Errorf("failed to get cluster client: %w", err)
	}

	// Use go-proxmox's VNetOptions struct
	vnetOpts := &goproxmox.VNetOptions{
		Name: vnetName,
		Zone: zoneName,
	}
	if tag > 0 {
		vnetOpts.Tag = tag
	}

	// Use library's NewSDNVNet function
	err = cluster.NewSDNVNet(ctx, vnetOpts)
	if err != nil {
		return fmt.Errorf("failed to create VNet %s: %w", vnetName, err)
	}

	logger.Debug(fmt.Sprintf("Created VNet %s in zone %s", vnetName, zoneName))
	return nil
}

// DeleteVNet removes an SDN VNet using go-proxmox library
func DeleteVNet(client *goproxmox.Client, vnetName string) error {
	ctx := context.Background()
	cluster, err := client.Cluster(ctx)
	if err != nil {
		return fmt.Errorf("failed to get cluster client: %w", err)
	}

	// Use library's DeleteSDNVNet function
	err = cluster.DeleteSDNVNet(ctx, vnetName)
	if err != nil {
		return fmt.Errorf("failed to delete VNet %s: %w", vnetName, err)
	}

	logger.Debug(fmt.Sprintf("Deleted VNet %s", vnetName))
	return nil
}

// DeleteSDNZone removes an SDN zone using go-proxmox library
func DeleteSDNZone(client *goproxmox.Client, zoneName string) error {
	ctx := context.Background()
	cluster, err := client.Cluster(ctx)
	if err != nil {
		return fmt.Errorf("failed to get cluster client: %w", err)
	}

	// Use library's DeleteSDNZone function
	err = cluster.DeleteSDNZone(ctx, zoneName)
	if err != nil {
		return fmt.Errorf("failed to delete SDN zone %s: %w", zoneName, err)
	}

	logger.Debug(fmt.Sprintf("Deleted SDN zone %s", zoneName))
	return nil
}

// ApplySDNChanges applies pending SDN configuration using go-proxmox library
func ApplySDNChanges(client *goproxmox.Client) error {
	ctx := context.Background()
	cluster, err := client.Cluster(ctx)
	if err != nil {
		return fmt.Errorf("failed to get cluster client: %w", err)
	}

	// Use library's SDNApply function - returns a Task
	task, err := cluster.SDNApply(ctx)
	if err != nil {
		return fmt.Errorf("failed to apply SDN changes: %w", err)
	}

	// Wait for task to complete
	err = task.Wait(ctx, 2*time.Second, 60*time.Second)
	if err != nil {
		return fmt.Errorf("SDN apply task failed: %w", err)
	}

	logger.Debug("Applied SDN changes successfully")
	return nil
}

// VNetExists checks if a VNet already exists using go-proxmox library
func VNetExists(client *goproxmox.Client, vnetName string) (bool, error) {
	ctx := context.Background()
	cluster, err := client.Cluster(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to get cluster client: %w", err)
	}

	// Use library's SDNVNet function - returns error if not found
	_, err = cluster.SDNVNet(ctx, vnetName)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return false, nil
		}
		return false, fmt.Errorf("failed to check VNet existence: %w", err)
	}
	return true, nil
}

// GetSDNZoneType looks up an SDN zone by name and returns its Proxmox zone type
// (e.g., "simple", "vxlan", "evpn", "vlan", "qinq") and whether it exists.
func GetSDNZoneType(ctx context.Context, client *goproxmox.Client, zoneName string) (string, bool, error) {
	type sdnZoneSummary struct {
		Name string `json:"zone"`
		Type string `json:"type"`
	}

	var zones []sdnZoneSummary
	if err := client.Get(ctx, "/cluster/sdn/zones", &zones); err != nil {
		return "", false, fmt.Errorf("failed to list SDN zones: %w", err)
	}

	for _, zone := range zones {
		if zone.Name == zoneName {
			return zone.Type, true, nil
		}
	}

	return "", false, nil
}

// ZoneExists checks if an SDN zone already exists without unmarshalling full zone options.
// Required until https://github.com/luthermonson/go-proxmox/pull/297 is merged
func ZoneExists(client *goproxmox.Client, zoneName string) (bool, error) {
	_, exists, err := GetSDNZoneType(context.Background(), client, zoneName)
	return exists, err
}

// BuildVNetOptionsForZone constructs VNet creation options appropriate for the target
// Proxmox SDN zone type:
//   - "simple": omits Tag (Proxmox rejects 'tag' on simple zones) and enables VlanAware
//     so single-node Proxmox hosts support trunked range VLANs out of the box.
//   - "vxlan" / "evpn": sets VNI Tag (16777215 for ludusnat, vxlanTagBase+rangeNumber for r{N})
//     and enables VlanAware.
//   - "qinq" / "vlan": enforces 802.1Q tag bounds (1..4094), enabling VlanAware on qinq.
func BuildVNetOptionsForZone(vnetName, zoneName, zoneType string, isNAT bool, vxlanTagBase, rangeNumber int) (*goproxmox.VNetOptions, error) {
	opts := &goproxmox.VNetOptions{
		Name: vnetName,
		Zone: zoneName,
	}

	switch strings.ToLower(strings.TrimSpace(zoneType)) {
	case SDNZoneTypeSimple:
		opts.VlanAware = true
		return opts, nil
	case SDNZoneTypeVLAN, SDNZoneTypeQinQ:
		var tag int
		if isNAT {
			if vxlanTagBase > 0 {
				tag = vxlanTagBase
			} else {
				tag = 4094
			}
		} else {
			tag = vxlanTagBase + rangeNumber
		}
		if tag < 1 || tag > 4094 {
			return nil, fmt.Errorf("SDN zone %q (type %s) requires VLAN tag in 1..4094, got %d for VNet %s", zoneName, zoneType, tag, vnetName)
		}
		opts.Tag = uint32(tag)
		opts.VlanAware = strings.EqualFold(zoneType, SDNZoneTypeQinQ)
		return opts, nil
	case SDNZoneTypeVXLAN, SDNZoneTypeEVPN, "":
		if isNAT {
			opts.Tag = 16777215
		} else {
			tag := vxlanTagBase + rangeNumber
			if tag < 1 || tag > 16777215 {
				return nil, fmt.Errorf("SDN zone %q (type %s) requires VXLAN VNI tag in 1..16777215, got %d for VNet %s", zoneName, zoneType, tag, vnetName)
			}
			opts.Tag = uint32(tag)
		}
		opts.VlanAware = true
		return opts, nil
	default:
		return nil, fmt.Errorf("unsupported Proxmox SDN zone type %q on zone %q", zoneType, zoneName)
	}
}

// EnsureSDNZone verifies that zoneName exists on Proxmox, or automatically creates a
// standalone "simple" SDN zone when running against a single-node Proxmox host in
// RemoteProxmox mode. Multi-node clusters still require a pre-configured VXLAN/EVPN zone.
func EnsureSDNZone(ctx context.Context, client *goproxmox.Client, zoneName string, clusterMode bool) (string, error) {
	if strings.TrimSpace(zoneName) == "" {
		zoneName = "ludus"
	}
	zoneType, exists, err := GetSDNZoneType(ctx, client, zoneName)
	if err != nil {
		return "", err
	}
	if exists {
		return zoneType, nil
	}
	if clusterMode {
		return "", fmt.Errorf("cluster mode requires a pre-configured SDN zone. Create zone '%s' in Proxmox with correct VXLAN peer IPs, then retry", zoneName)
	}
	if err := CreateSimpleSDNZone(client, zoneName); err != nil {
		return "", err
	}
	if err := ApplySDNChanges(client); err != nil {
		return "", err
	}
	logger.Info(fmt.Sprintf("Auto-created standalone Proxmox SDN simple zone '%s'", zoneName))
	return SDNZoneTypeSimple, nil
}

// GetVNetSubnets returns all subnets for a VNet using go-proxmox library
func GetVNetSubnets(client *goproxmox.Client, vnetName string) ([]*goproxmox.VNetSubnet, error) {
	ctx := context.Background()
	cluster, err := client.Cluster(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster client: %w", err)
	}

	// Use library's SDNSubnets function
	return cluster.SDNSubnets(ctx, vnetName)
}

// GetAllVNets returns all VNets using go-proxmox library
func GetAllVNets(client *goproxmox.Client) ([]*goproxmox.VNet, error) {
	ctx := context.Background()
	cluster, err := client.Cluster(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster client: %w", err)
	}

	// Use library's SDNVNets function
	return cluster.SDNVNets(ctx)
}

// GetAllSDNZones returns all SDN zones using go-proxmox library
func GetAllSDNZones(client *goproxmox.Client, typeFilter ...string) ([]*goproxmox.SDNZone, error) {
	ctx := context.Background()
	cluster, err := client.Cluster(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster client: %w", err)
	}

	// Use library's SDNZones function with optional type filter
	return cluster.SDNZones(ctx, typeFilter...)
}

// manageRangeVNet creates or deletes a VNet for a range using go-proxmox library
// This replaces the old manageVmbrInterfaceLocally function that edited /etc/network/interfaces
func manageRangeVNet(rangeID string, rangeNumber int, present bool) error {
	vnetName := fmt.Sprintf("r%d", rangeNumber) // e.g., "r1", "r2"
	ctx := context.Background()

	// Get root proxmox client for SDN operations
	client, err := GetRootGoProxmoxClient()
	if err != nil {
		return fmt.Errorf("failed to get proxmox client: %w", err)
	}

	cluster, err := client.Cluster(ctx)
	if err != nil {
		return fmt.Errorf("failed to get cluster client: %w", err)
	}

	// Get configured zone name with fallback to default
	zoneName := ServerConfiguration.SDNZone
	if zoneName == "" {
		zoneName = "ludus"
	}

	if present {
		// Check if VNet already exists using library's SDNVNet function
		_, err := cluster.SDNVNet(ctx, vnetName)
		if err == nil {
			logger.Debug(fmt.Sprintf("VNet %s already exists, skipping creation", vnetName))
			addRouteForRangeNetworkInVNet(rangeNumber)
			return nil
		}

		clusterMode, err := IsClusterMode()
		if err != nil {
			return fmt.Errorf("failed to check cluster mode for SDN zone %s: %w", zoneName, err)
		}
		zoneType, err := EnsureSDNZone(ctx, client, zoneName, clusterMode)
		if err != nil {
			return err
		}

		vnetOpts, err := BuildVNetOptionsForZone(vnetName, zoneName, zoneType, false, ServerConfiguration.VXLANTagBase, rangeNumber)
		if err != nil {
			return err
		}
		err = cluster.NewSDNVNet(ctx, vnetOpts)
		if err != nil {
			return fmt.Errorf("failed to create VNet %s: %w", vnetName, err)
		}

		// Apply SDN changes using library's SDNApply (returns Task)
		task, err := cluster.SDNApply(ctx)
		if err != nil {
			return fmt.Errorf("failed to apply SDN changes: %w", err)
		}
		err = task.Wait(ctx, 2*time.Second, 60*time.Second)
		if err != nil {
			return fmt.Errorf("SDN apply task failed: %w", err)
		}

		// Add the route through the range router for this range network
		addRouteForRangeNetworkInVNet(rangeNumber)

		logger.Debug(fmt.Sprintf("Created VNet %s (zone: %s, type: %s, tag: %d) for range %s", vnetName, zoneName, zoneType, vnetOpts.Tag, rangeID))

	} else {
		// Delete VNet using library's DeleteSDNVNet function
		err = cluster.DeleteSDNVNet(ctx, vnetName)
		if err != nil {
			// If VNet doesn't exist, that's OK
			if !strings.Contains(err.Error(), "does not exist") && !strings.Contains(err.Error(), "not found") {
				return fmt.Errorf("failed to delete VNet %s: %w", vnetName, err)
			}
			logger.Debug(fmt.Sprintf("VNet %s does not exist, skipping deletion", vnetName))
			return nil
		}

		// Apply SDN changes
		task, err := cluster.SDNApply(ctx)
		if err != nil {
			return fmt.Errorf("failed to apply SDN changes after deletion: %w", err)
		}
		err = task.Wait(ctx, 2*time.Second, 60*time.Second)
		if err != nil {
			return fmt.Errorf("SDN apply task failed: %w", err)
		}

		// Remove the route through the range router for this range network
		removeRouteForRangeNetworkInVNet(rangeNumber)

		logger.Debug(fmt.Sprintf("Deleted VNet %s for range %s", vnetName, rangeID))
	}

	return nil
}

// setupNATVNet creates the NAT VNet (ludusnat) for the 192.0.2.0/24 network
// when SDN is active (cluster mode or RemoteProxmox VM mode).
func setupNATVNet() error {
	ctx := context.Background()

	// Check if SDN is active
	if !UseSDN {
		logger.Debug("SDN disabled, skipping SDN NAT VNet setup (using standalone vmbr1000)")
		return nil
	}

	client, err := GetRootGoProxmoxClient()
	if err != nil {
		return fmt.Errorf("failed to get proxmox client: %w", err)
	}

	cluster, err := client.Cluster(ctx)
	if err != nil {
		return fmt.Errorf("failed to get cluster client: %w", err)
	}

	// Get configured zone name with fallback to default
	zoneName := ServerConfiguration.SDNZone
	if zoneName == "" {
		zoneName = "ludus"
	}

	clusterMode, err := IsClusterMode()
	if err != nil {
		return fmt.Errorf("failed to detect cluster mode: %w", err)
	}
	zoneType, err := EnsureSDNZone(ctx, client, zoneName, clusterMode)
	if err != nil {
		return err
	}

	natVNet := NATVNetName
	if ServerConfiguration.RemoteProxmox && strings.TrimSpace(ServerConfiguration.LudusNATInterface) != "" {
		natVNet = ServerConfiguration.EffectiveLudusNATInterface()
	}

	// Check if already exists using library's SDNVNet function
	_, err = cluster.SDNVNet(ctx, natVNet)
	if err != nil {
		vnetOpts, optsErr := BuildVNetOptionsForZone(natVNet, zoneName, zoneType, true, ServerConfiguration.VXLANTagBase, 0)
		if optsErr != nil {
			return optsErr
		}
		err = cluster.NewSDNVNet(ctx, vnetOpts)
		if err != nil {
			return fmt.Errorf("failed to create NAT VNet %s: %w", natVNet, err)
		}

		// Apply changes using library's SDNApply
		task, err := cluster.SDNApply(ctx)
		if err != nil {
			return fmt.Errorf("failed to apply SDN changes: %w", err)
		}
		err = task.Wait(ctx, 2*time.Second, 60*time.Second)
		if err != nil {
			return fmt.Errorf("SDN apply task failed: %w", err)
		}
		logger.Debug(fmt.Sprintf("Created NAT VNet %s in zone %s (type: %s)", natVNet, zoneName, zoneType))
	} else {
		logger.Debug(fmt.Sprintf("VNet %s already exists, ensuring ACLs", natVNet))
	}

	// Make sure all ludus users have SDN.Use on the ludusnat vnet
	SDNVNetACL := goproxmox.ACLOptions{
		Path:      fmt.Sprintf("/sdn/zones/%s/%s", zoneName, natVNet),
		Groups:    "ludus_users",
		Roles:     "PVESDNUser",
		Propagate: goproxmox.IntOrBool(true),
		Delete:    goproxmox.IntOrBool(false),
	}
	logger.Debug(fmt.Sprintf("Setting permissions for group 'ludus_users' to SDN VNet '%s'\n", natVNet))
	err = client.UpdateACL(ctx, SDNVNetACL)
	if err != nil {
		return errors.New("unable to set permissions for group: " + err.Error())
	}

	return nil
}

// setupSDNZone ensures the Ludus SDN zone exists when SDN is enabled (cluster mode or
// RemoteProxmox VM mode). On standalone single-node Proxmox in RemoteProxmox mode, it
// auto-creates a 'simple' SDN zone if not already present.
func setupSDNZone() error {
	if !UseSDN {
		logger.Debug("SDN disabled, skipping SDN zone setup (using vmbr management)")
		return nil
	}

	client, err := GetRootGoProxmoxClient()
	if err != nil {
		return fmt.Errorf("failed to get proxmox client: %w", err)
	}

	clusterMode, err := IsClusterMode()
	if err != nil {
		return fmt.Errorf("failed to detect cluster mode: %w", err)
	}

	zoneName := ServerConfiguration.SDNZone
	if zoneName == "" {
		zoneName = "ludus"
	}

	zoneType, err := EnsureSDNZone(context.Background(), client, zoneName, clusterMode)
	if err != nil {
		return err
	}
	logger.Debug(fmt.Sprintf("Using SDN zone %s (type: %s)", zoneName, zoneType))
	return nil
}

func addRouteForRangeNetworkInVNet(rangeNumber int) error {
	return routeForRangeNetworkInVNetAction(rangeNumber, true)
}

func removeRouteForRangeNetworkInVNet(rangeNumber int) error {
	return routeForRangeNetworkInVNetAction(rangeNumber, false)
}

func routeForRangeNetworkInVNetAction(rangeNumber int, present bool) error {

	// Edit the /etc/network/if-up.d/sdn-routes file and make sure it contains an ip route command for the range network
	sdnRoutesFile := "/etc/network/if-up.d/sdn-routes"

	// Create the file if it doesn't exist and make it executable
	if !FileExists(sdnRoutesFile) {
		touch(sdnRoutesFile)
		os.Chmod(sdnRoutesFile, 0755)
		// The file must start with a shebang or it will throw an `exec format error`
		os.WriteFile(sdnRoutesFile, []byte("#!/bin/sh\n"), 0755)
	}

	natIface := NATVNetName
	if ServerConfiguration.RemoteProxmox {
		natIface = ServerConfiguration.EffectiveLudusNATInterface()
	}

	block := fmt.Sprintf(`
if [ "$IFACE" = "r%d" ] || [ "$IFACE" = "%s" ]; then
	ip route replace 10.%d.0.0/16 via 192.0.2.%d dev %s
fi
	`, rangeNumber, natIface, rangeNumber, 100+rangeNumber, natIface)
	_, err := applyBlockInFileAtPath(sdnRoutesFile, fmt.Sprintf("# LUDUS MANAGED BLOCK FOR RANGE %d {mark}", rangeNumber), block, present)
	if err != nil {
		return fmt.Errorf("failed to apply block in file: %w", err)
	}
	if present {
		// Add/replace the route immediately (idempotent if route already exists)
		err = Run(fmt.Sprintf("ip route replace 10.%d.0.0/16 via 192.0.2.%d dev %s", rangeNumber, 100+rangeNumber, natIface), "/tmp", "/tmp/sdn-routes.log")
		if err != nil {
			return fmt.Errorf("failed to add route: %w", err)
		}
	} else {
		_ = Run(fmt.Sprintf("ip route del 10.%d.0.0/16 via 192.0.2.%d dev %s", rangeNumber, 100+rangeNumber, natIface), "/tmp", "/tmp/sdn-routes.log")
	}
	return nil
}
