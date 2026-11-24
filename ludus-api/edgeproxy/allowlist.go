package edgeproxy

import (
	"fmt"
	"net/netip"
	"strings"
)

const (
	// DefaultEdgeNATIP is ludus-edge's own IP on the ludusnat SDN VNet (192.0.2.254).
	DefaultEdgeNATIP = "192.0.2.254"
	// DefaultPackerPortMin is the lowest allowed ephemeral reverse HTTP port on ludusnat.
	DefaultPackerPortMin = 8350
	// DefaultPackerPortMax is the highest allowed ephemeral reverse HTTP port on ludusnat.
	DefaultPackerPortMax = 8399
)

var (
	ludusNATPrefix = netip.MustParsePrefix("192.0.2.0/24")
	edgeNATSelfIP  = netip.MustParseAddr(DefaultEdgeNATIP)
)

// IsAllowedRangeAddr returns true iff addr belongs strictly to a Ludus range network:
//   - 192.0.2.0/24 (ludusnat range router WANs and temporary Packer build IPs), EXCLUDING 192.0.2.254 (ludus-edge itself)
//   - 10.1.0.0/16 .. 10.254.0.0/16 (Range 1..254 internal VLAN subnets)
//
// All management/LAN/loopback/RFC1918 networks (including 10.0.0.0/16 where 10.0.20.0/24 lives,
// 127.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, IPv6, link-local, multicast) are rejected in O(1).
func IsAllowedRangeAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.Is4() {
		return false
	}
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	if ludusNATPrefix.Contains(addr) {
		return addr != edgeNATSelfIP
	}
	b := addr.As4()
	// 10.<range_id>.0.0/16 for range_id in [1..254]; explicitly rejects 10.0.0.0/16 and 10.255.0.0/16.
	return b[0] == 10 && b[1] >= 1 && b[1] <= 254
}

// ParseAndValidateDialTarget parses an IPv4:port literal and enforces IsAllowedRangeAddr + non-zero port.
// Hostnames are rejected so DNS resolution can never rebind to a forbidden LAN/loopback IP on ludus-edge.
func ParseAndValidateDialTarget(raw string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(strings.TrimSpace(raw))
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid IP:port target %q: %w", raw, err)
	}
	if ap.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("target port must be non-zero in %q", raw)
	}
	if !IsAllowedRangeAddr(ap.Addr()) {
		return netip.AddrPort{}, fmt.Errorf("target %s is outside allowed Ludus range subnets (192.0.2.0/24 excl .254, 10.1.0.0/16..10.254.0.0/16)", ap.String())
	}
	return ap, nil
}

// ValidatePackerListenPort checks that port falls within the dedicated Packer preseed range.
func ValidatePackerListenPort(port uint16, minPort uint16, maxPort uint16) error {
	if minPort == 0 {
		minPort = DefaultPackerPortMin
	}
	if maxPort == 0 {
		maxPort = DefaultPackerPortMax
	}
	if port < minPort || port > maxPort {
		return fmt.Errorf("reverse listen port %d outside allowed Packer range [%d..%d]", port, minPort, maxPort)
	}
	return nil
}
