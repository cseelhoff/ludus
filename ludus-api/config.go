package ludusapi

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

const ludusInstallPath string = "/opt/ludus"
const LudusInstallPath = ludusInstallPath // Export the path for use in plugins

// Default listen ports used when config.yml omits the corresponding keys
const (
	DefaultPort      = 8080
	DefaultAdminPort = 8081
)

// Proxmox authentication modes supported by Ludus when targeting an external Proxmox host.
const (
	ProxmoxAuthModePerUserPVE   = "per_user_pve"
	ProxmoxAuthModeServiceToken = "service_token"
)

// Configurations exported
type Configuration struct {
	ProxmoxNode               string        `mapstructure:"proxmox_node" yaml:"proxmox_node"`
	ProxmoxInterface          string        `mapstructure:"proxmox_interface" yaml:"proxmox_interface"`
	ProxmoxInvalidCert        bool          `mapstructure:"proxmox_invalid_cert" yaml:"proxmox_invalid_cert"`
	ProxmoxTLSVerify          *bool         `mapstructure:"proxmox_tls_verify" yaml:"proxmox_tls_verify,omitempty"`
	ProxmoxURL                string        `mapstructure:"proxmox_url" yaml:"proxmox_url"`
	ProxmoxHostname           string        `mapstructure:"proxmox_hostname" yaml:"proxmox_hostname"`
	ProxmoxLocalIP            string        `mapstructure:"proxmox_local_ip" yaml:"proxmox_local_ip"`
	ProxmoxPublicIP           string        `mapstructure:"proxmox_public_ip" yaml:"proxmox_public_ip"`
	ProxmoxGateway            string        `mapstructure:"proxmox_gateway" yaml:"proxmox_gateway"`
	ProxmoxNetmask            string        `mapstructure:"proxmox_netmask" yaml:"proxmox_netmask"`
	ProxmoxVMStoragePool      string        `mapstructure:"proxmox_vm_storage_pool" yaml:"proxmox_vm_storage_pool"`
	ProxmoxVMStorageFormat    string        `mapstructure:"proxmox_vm_storage_format" yaml:"proxmox_vm_storage_format"`
	ProxmoxISOStoragePool     string        `mapstructure:"proxmox_iso_storage_pool" yaml:"proxmox_iso_storage_pool"`
	LudusNATInterface         string        `mapstructure:"ludus_nat_interface" yaml:"ludus_nat_interface"`
	PreventUserAnsibleAdd     bool          `mapstructure:"prevent_user_ansible_add" yaml:"prevent_user_ansible_add"`
	SSORequireExistingUser    bool          `mapstructure:"sso_require_existing_user" yaml:"sso_require_existing_user"`
	CreateDefaultRange        bool          `mapstructure:"create_default_range" yaml:"create_default_range"`
	LicenseKey                string        `mapstructure:"license_key" yaml:"license_key"`
	ExposeAdminPort           bool          `mapstructure:"expose_admin_port" yaml:"expose_admin_port"`
	RegisterDefaultSource     bool          `mapstructure:"register_default_source" yaml:"register_default_source"`
	SyncSourcesOnStartup      bool          `mapstructure:"sync_sources_on_startup" yaml:"sync_sources_on_startup"`
	Port                      int           `mapstructure:"port" yaml:"port"`
	AdminPort                 int           `mapstructure:"admin_port" yaml:"admin_port"`
	ReservedRangeNumbers      []int32       `mapstructure:"reserved_range_numbers" yaml:"reserved_range_numbers"`
	DataDirectory             string        `mapstructure:"data_directory" yaml:"data_directory"`
	DatabaseEncryptionKey     string        `mapstructure:"database_encryption_key" yaml:"database_encryption_key"`
	DatabaseEncryptionKeyFile string        `mapstructure:"database_encryption_key_file" yaml:"database_encryption_key_file,omitempty"`
	WireguardPort             int           `mapstructure:"wireguard_port" yaml:"wireguard_port"`
	MaxLogHistory             int           `mapstructure:"max_log_history" yaml:"max_log_history"` // Max number of log history entries to keep per range/user (default: 100)
	InactivityShutdownTimeout time.Duration `mapstructure:"inactivity_shutdown_timeout" yaml:"inactivity_shutdown_timeout"`
	// Cluster mode settings
	ClusterMode  bool   `mapstructure:"cluster_mode" yaml:"cluster_mode"`     // Auto-detected via API during startup, can be overridden
	SDNZone      string `mapstructure:"sdn_zone" yaml:"sdn_zone"`             // The SDN zone name for Ludus networking (default: "ludus")
	VXLANTagBase int    `mapstructure:"vxlan_tag_base" yaml:"vxlan_tag_base"` // Base VXLAN tag (VNI) added to range number (default: 0)
	// Remote Proxmox VM mode settings (run ludus-server inside a non-nested VM targeting an external Proxmox host/cluster)
	RemoteProxmox            bool     `mapstructure:"remote_proxmox" yaml:"remote_proxmox"`
	ProxmoxPinToNode         bool     `mapstructure:"proxmox_pin_to_node" yaml:"proxmox_pin_to_node"`
	ProxmoxAllowedNodes      []string `mapstructure:"proxmox_allowed_nodes" yaml:"proxmox_allowed_nodes,omitempty"`
	ProxmoxRealm             string   `mapstructure:"proxmox_realm" yaml:"proxmox_realm"`
	ProxmoxAuthMode          string   `mapstructure:"proxmox_auth_mode" yaml:"proxmox_auth_mode,omitempty"`
	ProxmoxAdminUser         string   `mapstructure:"proxmox_admin_user" yaml:"proxmox_admin_user"`
	ProxmoxAdminPasswordFile string   `mapstructure:"proxmox_admin_password_file" yaml:"proxmox_admin_password_file"`
	ProxmoxAPITokenID        string   `mapstructure:"proxmox_api_token_id" yaml:"proxmox_api_token_id,omitempty"`
	ProxmoxAPITokenFile      string   `mapstructure:"proxmox_api_token_file" yaml:"proxmox_api_token_file,omitempty"`
	ProxmoxRootTokenID       string   `mapstructure:"proxmox_root_token_id" yaml:"proxmox_root_token_id"`
	ProxmoxRootTokenFile     string   `mapstructure:"proxmox_root_token_file" yaml:"proxmox_root_token_file"`
	// Container mode & listener settings (run ludus-server unprivileged in an OCI container)
	ContainerMode bool  `mapstructure:"container_mode" yaml:"container_mode,omitempty"`
	TLSEnabled    *bool `mapstructure:"tls_enabled" yaml:"tls_enabled,omitempty"`
	// Edge VM self-provisioning & userspace mTLS proxy settings (ludus -> ludus-edge)
	EdgeAutoProvision      bool     `mapstructure:"edge_auto_provision" yaml:"edge_auto_provision,omitempty"`
	EdgeVMID               int      `mapstructure:"edge_vmid" yaml:"edge_vmid,omitempty"`
	EdgeVMName             string   `mapstructure:"edge_vm_name" yaml:"edge_vm_name,omitempty"`
	EdgeVMIP               string   `mapstructure:"edge_vm_ip" yaml:"edge_vm_ip,omitempty"`
	EdgeVMCIDRPrefix       int      `mapstructure:"edge_vm_cidr_prefix" yaml:"edge_vm_cidr_prefix,omitempty"`
	EdgeVMGateway          string   `mapstructure:"edge_vm_gateway" yaml:"edge_vm_gateway,omitempty"`
	EdgeVMBridge           string   `mapstructure:"edge_vm_bridge" yaml:"edge_vm_bridge,omitempty"`
	EdgeAllowedClientCIDRs []string `mapstructure:"edge_allowed_client_cidrs" yaml:"edge_allowed_client_cidrs,omitempty"`
	EdgeISOPath            string   `mapstructure:"edge_iso_path" yaml:"edge_iso_path,omitempty"`
	EdgeStateDir           string   `mapstructure:"edge_state_dir" yaml:"edge_state_dir,omitempty"`
	EdgeProxyEnabled       bool     `mapstructure:"edge_proxy_enabled" yaml:"edge_proxy_enabled,omitempty"`
	EdgeProxyAddr          string   `mapstructure:"edge_proxy_addr" yaml:"edge_proxy_addr,omitempty"`
	EdgeProxyCAFile        string   `mapstructure:"edge_proxy_ca_file" yaml:"edge_proxy_ca_file,omitempty"`
	EdgeProxyCertFile      string   `mapstructure:"edge_proxy_cert_file" yaml:"edge_proxy_cert_file,omitempty"`
	EdgeProxyKeyFile       string   `mapstructure:"edge_proxy_key_file" yaml:"edge_proxy_key_file,omitempty"`
	EdgeLocalSOCKSPort     int      `mapstructure:"edge_local_socks_port" yaml:"edge_local_socks_port,omitempty"`
	EdgeNATIP              string   `mapstructure:"edge_nat_ip" yaml:"edge_nat_ip,omitempty"`
	EdgeNATMAC             string   `mapstructure:"edge_nat_mac" yaml:"edge_nat_mac,omitempty"`
	PackerHTTPPortMin      int      `mapstructure:"packer_http_port_min" yaml:"packer_http_port_min,omitempty"`
	PackerHTTPPortMax      int      `mapstructure:"packer_http_port_max" yaml:"packer_http_port_max,omitempty"`
	// Pre-baked WireGuard client slot pool file (250 slots derived on ludus-edge)
	WireguardPoolFile string `mapstructure:"wireguard_pool_file" yaml:"wireguard_pool_file,omitempty"`
	// Declarative OIDC provider settings (e.g. Sophon Keycloak)
	OIDCEnabled          bool     `mapstructure:"oidc_enabled" yaml:"oidc_enabled,omitempty"`
	OIDCDisplayName      string   `mapstructure:"oidc_display_name" yaml:"oidc_display_name,omitempty"`
	OIDCIssuerURL        string   `mapstructure:"oidc_issuer_url" yaml:"oidc_issuer_url,omitempty"`
	OIDCClientID         string   `mapstructure:"oidc_client_id" yaml:"oidc_client_id,omitempty"`
	OIDCClientSecretFile string   `mapstructure:"oidc_client_secret_file" yaml:"oidc_client_secret_file,omitempty"`
	OIDCSkipTLSVerify    bool     `mapstructure:"oidc_skip_tls_verify" yaml:"oidc_skip_tls_verify,omitempty"`
	OIDCExtraAudiences   []string `mapstructure:"oidc_extra_audiences" yaml:"oidc_extra_audiences,omitempty"`
	OIDCAllowedGroups    []string `mapstructure:"oidc_allowed_groups" yaml:"oidc_allowed_groups,omitempty"`
	OIDCAdminGroups      []string `mapstructure:"oidc_admin_groups" yaml:"oidc_admin_groups,omitempty"`
	// Quota defaults - applied to users who don't have explicit quotas or group defaults
	// 0 means unlimited
	DefaultQuotaRAM    int `mapstructure:"default_quota_ram" yaml:"default_quota_ram"`
	DefaultQuotaCPU    int `mapstructure:"default_quota_cpu" yaml:"default_quota_cpu"`
	DefaultQuotaVMs    int `mapstructure:"default_quota_vms" yaml:"default_quota_vms"`
	DefaultQuotaRanges int `mapstructure:"default_quota_ranges" yaml:"default_quota_ranges"`
}

var ServerConfiguration = Configuration{SSORequireExistingUser: true, CreateDefaultRange: true}
var ConfigMu sync.RWMutex

func (s *Server) ParseConfig() {
	// Set the file name of the configurations file
	viper.SetConfigName("config")

	// Set the path to look for the configurations file
	viper.AddConfigPath(ludusInstallPath)

	// Enable viper to read Environment Variables
	viper.AutomaticEnv()

	viper.SetConfigType("yaml")

	// Set defaults
	viper.SetDefault("proxmox_invalid_cert", true)
	viper.SetDefault("proxmox_url", "https://127.0.0.1:8006")
	viper.SetDefault("proxmox_public_ip", "127.0.0.1")
	viper.SetDefault("proxmox_vm_storage_pool", "local")
	viper.SetDefault("proxmox_vm_storage_format", "qcow2")
	viper.SetDefault("proxmox_iso_storage_pool", "local")
	viper.SetDefault("ludus_nat_interface", "vmbr1000")
	viper.SetDefault("prevent_user_ansible_add", false)
	viper.SetDefault("sso_require_existing_user", true)
	viper.SetDefault("create_default_range", true)
	viper.SetDefault("register_default_source", true)
	viper.SetDefault("sync_sources_on_startup", true)
	viper.SetDefault("data_directory", "/opt/ludus/db")
	viper.SetDefault("database_encryption_key", "hZD6RwYxrcQ7CS4lRxjdKI7thWp3jg48")
	viper.SetDefault("wireguard_port", 51820)
	viper.SetDefault("port", DefaultPort)
	viper.SetDefault("admin_port", DefaultAdminPort)
	// Do not set a default for cluster_mode to force viper to leave it unset unless provided,
	// so we can detect if user has explicitly set it or not and fallback to API if unset.
	// (See IsClusterMode in sdn.go for logic)
	viper.SetDefault("remote_proxmox", false)
	viper.SetDefault("container_mode", false)
	viper.SetDefault("proxmox_pin_to_node", false)
	viper.SetDefault("proxmox_admin_user", "root@pam")
	viper.SetDefault("sdn_zone", "ludus") // Default SDN zone name
	viper.SetDefault("vxlan_tag_base", 0) // Base VXLAN tag added to range number
	viper.SetDefault("default_quota_ram", 0)
	viper.SetDefault("default_quota_cpu", 0)
	viper.SetDefault("default_quota_vms", 0)
	viper.SetDefault("default_quota_ranges", 0)
	viper.SetDefault("max_log_history", 100)           // Max log history entries per range/user
	viper.SetDefault("inactivity_shutdown_timeout", 0) // Disabled by default
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file, %s", err)
	}

	// Hold the write lock around the initial unmarshal for symmetry with
	// OnConfigChange — the scheduler hasn't started yet, but future concurrent
	// readers during ParseConfig wouldn't have a safe time-window without this.
	ConfigMu.Lock()
	err := viper.Unmarshal(&ServerConfiguration)
	ServerConfiguration.ApplyRemoteProxmoxDefaults()
	ConfigMu.Unlock()
	if err != nil {
		log.Fatalf("Unable to decode into struct, %v", err)
	}
	if err := ServerConfiguration.LoadEncryptionKeyFromFileIfConfigured(); err != nil {
		log.Fatalf("Unable to load database encryption key: %v", err)
	}
	// Make sure the database encryption key is 32 characters long
	if len(ServerConfiguration.DatabaseEncryptionKey) != 32 {
		log.Fatalf("Database encryption key must be 32 characters long")
	}
	if err := ServerConfiguration.ApplyPortDefaultsAndValidate(); err != nil {
		log.Fatalf("%v", err)
	}
	// If there is no license in the config, set it to community
	if ServerConfiguration.LicenseKey == "" || ServerConfiguration.LicenseKey == "community" {
		s.Entitlements = []string{}
		s.LicenseValid = true
		s.LicenseMessage = "community license"
	} else {
		s.LicenseMessage = ""
		s.LicenseKey = ServerConfiguration.LicenseKey
		s.checkLicense()
	}
	log.Println("Using configuration file: ", viper.ConfigFileUsed())

	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		ConfigMu.Lock()
		defer ConfigMu.Unlock()
		if err := viper.Unmarshal(&ServerConfiguration); err != nil {
			log.Printf("Error reloading config: %v", err)
		} else {
			ServerConfiguration.ApplyRemoteProxmoxDefaults()
			log.Println("Configuration reloaded from file")
		}
	})
}

// EffectiveProxmoxRealm returns the configured Proxmox user realm ("pve" by default when
// RemoteProxmox is enabled, otherwise "pam").
func (c *Configuration) EffectiveProxmoxRealm() string {
	if realm := strings.TrimSpace(c.ProxmoxRealm); realm != "" {
		return realm
	}
	if c.RemoteProxmox {
		return "pve"
	}
	return "pam"
}

// EffectiveProxmoxAdminUser returns the Proxmox admin user ID (including @realm) used for
// ticket-authenticated user/password/bootstrap operations.
func (c *Configuration) EffectiveProxmoxAdminUser() string {
	admin := strings.TrimSpace(c.ProxmoxAdminUser)
	if admin == "" {
		return "root@pam"
	}
	if !strings.Contains(admin, "@") {
		return admin + "@pam"
	}
	return admin
}

// EffectiveLudusNATInterface returns the NAT transit interface name. When RemoteProxmox
// is enabled and the legacy host default ("vmbr1000") or empty string was left in place,
// it normalizes to "ludusnat" to match the Proxmox SDN NAT VNet.
func (c *Configuration) EffectiveLudusNATInterface() string {
	iface := strings.TrimSpace(c.LudusNATInterface)
	if c.RemoteProxmox && (iface == "" || iface == "vmbr1000") {
		return NATVNetName
	}
	if iface == "" {
		return "vmbr1000"
	}
	return iface
}

// ResolveProxmoxHostname derives the reachable Proxmox API hostname/IP for Ansible modules
// (PROXMOX_HOSTNAME -> api_host). When ProxmoxHostname is unset and ProxmoxURL points to a
// non-loopback host (or RemoteProxmox is enabled), the host component of ProxmoxURL is used
// so Ansible does not depend on /etc/hosts resolution of short node names.
func (c *Configuration) ResolveProxmoxHostname() string {
	if h := strings.TrimSpace(c.ProxmoxHostname); h != "" {
		return h
	}
	if rawURL := strings.TrimSpace(c.ProxmoxURL); rawURL != "" {
		if parsed, err := url.Parse(rawURL); err == nil {
			if host := parsed.Hostname(); host != "" {
				if c.RemoteProxmox || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
					return host
				}
			}
		}
	}
	return c.ProxmoxNode
}

// EffectiveProxmoxAuthMode returns "service_token" or "per_user_pve".
// When unset, it auto-selects "service_token" if proxmox_api_token_id is configured
// or if container_mode is enabled without a proxmox_admin_password_file.
func (c *Configuration) EffectiveProxmoxAuthMode() string {
	mode := strings.ToLower(strings.TrimSpace(c.ProxmoxAuthMode))
	switch mode {
	case ProxmoxAuthModeServiceToken:
		return ProxmoxAuthModeServiceToken
	case ProxmoxAuthModePerUserPVE:
		return ProxmoxAuthModePerUserPVE
	}
	if strings.TrimSpace(c.ProxmoxAPITokenID) != "" {
		return ProxmoxAuthModeServiceToken
	}
	if strings.TrimSpace(os.Getenv("LUDUS_PROXMOX_API_TOKEN_ID")) != "" {
		return ProxmoxAuthModeServiceToken
	}
	if c.ContainerMode && strings.TrimSpace(c.ProxmoxAdminPasswordFile) == "" {
		return ProxmoxAuthModeServiceToken
	}
	return ProxmoxAuthModePerUserPVE
}

// IsServiceTokenAuthMode reports whether Ludus authenticates all Proxmox API calls
// with a single shared service token and performs zero Proxmox IAM/ACL mutations.
func (c *Configuration) IsServiceTokenAuthMode() bool {
	return c.EffectiveProxmoxAuthMode() == ProxmoxAuthModeServiceToken
}

// IsTLSEnabled reports whether the Ludus HTTP listeners terminate TLS directly
// (default true when tls_enabled is omitted).
func (c *Configuration) IsTLSEnabled() bool {
	return c.TLSEnabled == nil || *c.TLSEnabled
}

// LoadEncryptionKeyFromFileIfConfigured loads DatabaseEncryptionKey from
// DatabaseEncryptionKeyFile (or LUDUS_DATABASE_ENCRYPTION_KEY_FILE) when set.
func (c *Configuration) LoadEncryptionKeyFromFileIfConfigured() error {
	keyFile := strings.TrimSpace(c.DatabaseEncryptionKeyFile)
	if envFile := strings.TrimSpace(os.Getenv("LUDUS_DATABASE_ENCRYPTION_KEY_FILE")); envFile != "" {
		keyFile = envFile
	}
	if keyFile == "" {
		return nil
	}
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("read database_encryption_key_file %q: %w", keyFile, err)
	}
	key := strings.TrimRight(string(raw), "\r\n")
	if len(key) != 32 {
		return fmt.Errorf("database_encryption_key_file %q must contain 32 bytes, got %d", keyFile, len(key))
	}
	c.DatabaseEncryptionKey = key
	return nil
}

// ApplyRemoteProxmoxDefaults normalizes derived realm, hostname, admin user, SDN zone,
// Proxmox URL base, TLS verification alias, container/edge defaults, and NAT interface defaults on Configuration.
func (c *Configuration) ApplyRemoteProxmoxDefaults() {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("LUDUS_CONTAINER_MODE")), "true") || strings.TrimSpace(os.Getenv("LUDUS_CONTAINER_MODE")) == "1" {
		c.ContainerMode = true
	}
	if c.ContainerMode {
		c.RemoteProxmox = true
	}
	if trimmedURL := strings.TrimSpace(c.ProxmoxURL); trimmedURL != "" {
		trimmedURL = strings.TrimRight(trimmedURL, "/")
		trimmedURL = strings.TrimSuffix(trimmedURL, "/api2/json")
		c.ProxmoxURL = strings.TrimRight(trimmedURL, "/")
	}
	if c.ProxmoxTLSVerify != nil {
		c.ProxmoxInvalidCert = !(*c.ProxmoxTLSVerify)
	}
	c.ProxmoxAuthMode = c.EffectiveProxmoxAuthMode()
	c.ProxmoxRealm = c.EffectiveProxmoxRealm()
	c.ProxmoxAdminUser = c.EffectiveProxmoxAdminUser()
	c.LudusNATInterface = c.EffectiveLudusNATInterface()
	c.ProxmoxHostname = c.ResolveProxmoxHostname()
	if strings.TrimSpace(c.SDNZone) == "" {
		c.SDNZone = "ludus"
	}
	dataDir := strings.TrimSpace(c.DataDirectory)
	if dataDir == "" {
		dataDir = filepath.Join(ludusInstallPath, "db")
	}
	if strings.TrimSpace(c.EdgeVMName) == "" {
		c.EdgeVMName = "ludus-edge"
	}
	if c.EdgeVMCIDRPrefix == 0 {
		c.EdgeVMCIDRPrefix = 24
	}
	if strings.TrimSpace(c.EdgeVMBridge) == "" {
		c.EdgeVMBridge = "vmbr0"
	}
	if strings.TrimSpace(c.EdgeISOPath) == "" {
		c.EdgeISOPath = filepath.Join(ludusInstallPath, "resources", "ludus-edge.iso")
	}
	if strings.TrimSpace(c.EdgeStateDir) == "" {
		c.EdgeStateDir = filepath.Join(dataDir, "edge")
	}
	if c.EdgeLocalSOCKSPort == 0 {
		c.EdgeLocalSOCKSPort = 1080
	}
	if strings.TrimSpace(c.EdgeNATIP) == "" {
		c.EdgeNATIP = "192.0.2.254"
	}
	if c.PackerHTTPPortMin == 0 {
		c.PackerHTTPPortMin = 8350
	}
	if c.PackerHTTPPortMax == 0 {
		c.PackerHTTPPortMax = 8360
	}
	if strings.TrimSpace(c.EdgeProxyAddr) == "" && strings.TrimSpace(c.EdgeVMIP) != "" && (c.EdgeProxyEnabled || c.EdgeAutoProvision) {
		c.EdgeProxyAddr = fmt.Sprintf("%s:8444", strings.TrimSpace(c.EdgeVMIP))
	}
	if strings.TrimSpace(c.WireguardPoolFile) == "" && (c.EdgeProxyEnabled || c.EdgeAutoProvision) {
		c.WireguardPoolFile = filepath.Join(c.EdgeStateDir, "wg_pool.json")
	}
	if strings.TrimSpace(c.EdgeProxyCAFile) == "" && c.EdgeAutoProvision {
		c.EdgeProxyCAFile = filepath.Join(c.EdgeStateDir, "ca.crt")
	}
	if strings.TrimSpace(c.EdgeProxyCertFile) == "" && c.EdgeAutoProvision {
		c.EdgeProxyCertFile = filepath.Join(c.EdgeStateDir, "client.crt")
	}
	if strings.TrimSpace(c.EdgeProxyKeyFile) == "" && c.EdgeAutoProvision {
		c.EdgeProxyKeyFile = filepath.Join(c.EdgeStateDir, "client.key")
	}
	c.OIDCIssuerURL = strings.TrimRight(strings.TrimSpace(c.OIDCIssuerURL), "/")
	if c.OIDCEnabled && strings.TrimSpace(c.OIDCDisplayName) == "" {
		c.OIDCDisplayName = "SSO"
	}
}

// EffectiveAllowedProxmoxNodes returns the explicit allowlist of Proxmox cluster nodes
// permitted to host range VMs, or nil if all online cluster nodes are permitted.
// When ProxmoxPinToNode is true, placement is strictly pinned to ProxmoxNode even when
// Proxmox SDN (e.g., VXLAN) is active across a multi-node cluster.
func (c *Configuration) EffectiveAllowedProxmoxNodes() []string {
	if c.ProxmoxPinToNode {
		if node := strings.TrimSpace(c.ProxmoxNode); node != "" {
			return []string{node}
		}
	}
	if len(c.ProxmoxAllowedNodes) == 0 {
		return nil
	}
	var allowed []string
	for _, raw := range c.ProxmoxAllowedNodes {
		node := strings.TrimSpace(raw)
		if node != "" && !slices.Contains(allowed, node) {
			allowed = append(allowed, node)
		}
	}
	return allowed
}

// IsProxmoxNodeAllowed reports whether node is permitted under EffectiveAllowedProxmoxNodes.
func (c *Configuration) IsProxmoxNodeAllowed(node string) bool {
	target := strings.TrimSpace(node)
	if target == "" {
		return false
	}
	allowed := c.EffectiveAllowedProxmoxNodes()
	if len(allowed) == 0 {
		return true
	}
	return slices.Contains(allowed, target)
}

// AllowedProxmoxNodes returns the active node allowlist under ConfigMu.
func AllowedProxmoxNodes() []string {
	ConfigMu.RLock()
	defer ConfigMu.RUnlock()
	return ServerConfiguration.EffectiveAllowedProxmoxNodes()
}

// IsProxmoxNodeAllowed reports whether node is allowed under the active ServerConfiguration.
func IsProxmoxNodeAllowed(node string) bool {
	ConfigMu.RLock()
	defer ConfigMu.RUnlock()
	return ServerConfiguration.IsProxmoxNodeAllowed(node)
}

// ConfiguredProxmoxRealm returns the active Proxmox realm under ConfigMu.
func ConfiguredProxmoxRealm() string {
	ConfigMu.RLock()
	defer ConfigMu.RUnlock()
	return ServerConfiguration.EffectiveProxmoxRealm()
}

// IsContainerMode reports whether Ludus is running in unprivileged OCI container mode.
func IsContainerMode() bool {
	ConfigMu.RLock()
	defer ConfigMu.RUnlock()
	return ServerConfiguration.ContainerMode
}

// IsProxmoxServiceTokenMode reports whether Proxmox authentication is configured
// in shared service-token mode (zero Proxmox @pve user or ACL mutations).
func IsProxmoxServiceTokenMode() bool {
	ConfigMu.RLock()
	defer ConfigMu.RUnlock()
	return ServerConfiguration.IsServiceTokenAuthMode()
}

// IsTLSEnabled reports whether TLS is enabled on the Ludus HTTP listeners.
func IsTLSEnabled() bool {
	ConfigMu.RLock()
	defer ConfigMu.RUnlock()
	return ServerConfiguration.IsTLSEnabled()
}

// ApplyPortDefaultsAndValidate backfills DefaultPort / DefaultAdminPort for
// unset values (zero) and validates that both ports are in range 1-65535 and
// distinct. Callers across ludus-api and ludus-server share this to keep the
// three config load paths (Viper, plain yaml.Decode, plain yaml.Unmarshal) in sync.
func (c *Configuration) ApplyPortDefaultsAndValidate() error {
	if c.Port == 0 {
		c.Port = DefaultPort
	}
	if c.AdminPort == 0 {
		c.AdminPort = DefaultAdminPort
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", c.Port)
	}
	if c.AdminPort < 1 || c.AdminPort > 65535 {
		return fmt.Errorf("admin_port must be between 1 and 65535, got %d", c.AdminPort)
	}
	if c.Port == c.AdminPort {
		return fmt.Errorf("port and admin_port must differ (got %d for both)", c.Port)
	}
	return nil
}
