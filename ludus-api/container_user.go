package ludusapi

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func validateContainerWorkspaceSlug(slug string) error {
	trimmed := strings.TrimSpace(slug)
	if trimmed == "" {
		return errors.New("workspace username cannot be empty")
	}
	if trimmed == "." || trimmed == ".." || strings.EqualFold(trimmed, "root") {
		return fmt.Errorf("invalid workspace username %q", slug)
	}
	if strings.ContainsAny(trimmed, `/\`) || filepath.Base(trimmed) != trimmed {
		return fmt.Errorf("workspace username %q must not contain path separators", slug)
	}
	return nil
}

func extraVarBool(extraVars map[string]interface{}, key string, defaultVal bool) bool {
	raw, ok := extraVars[key]
	if !ok || raw == nil {
		return defaultVal
	}
	switch v := raw.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true") || strings.TrimSpace(v) == "1"
	default:
		return defaultVal
	}
}

func defaultContainerRangeConfigYAML(userID string) string {
	return fmt.Sprintf(`# yaml-language-server: $schema=https://docs.ludus.cloud/schemas/range-config.json

ludus:
  - vm_name: "%s-kali"
    hostname: "%s-kali"
    template: kali-x64-desktop-template
    vlan: 99
    ip_last_octet: 1
    ram_gb: 4
    cpus: 2
    linux: true

network:
  inter_vlan_default: REJECT
`, userID, userID)
}

// provisionContainerUserWorkspace creates per-user Ansible and Packer workspaces
// directly in Go when running in container_mode, replacing add-user.yml (no host
// useradd, /etc/passwd mutation, chown, or local /etc/wireguard/wg0.conf edits).
func provisionContainerUserWorkspace(extraVars map[string]interface{}) error {
	return provisionContainerUserWorkspaceAt(ludusInstallPath, extraVars)
}

func provisionContainerUserWorkspaceAt(baseDir string, extraVars map[string]interface{}) error {
	username, _ := extraVars["username"].(string)
	if err := validateContainerWorkspaceSlug(username); err != nil {
		return err
	}
	userID, _ := extraVars["user_id"].(string)
	hasDefaultRange := extraVarBool(extraVars, "user_has_default_range", false)

	userRoot := filepath.Join(baseDir, "users", username)
	subdirs := []string{
		userRoot,
		filepath.Join(userRoot, "packer", "tmp"),
		filepath.Join(userRoot, "packer", "packer_cache"),
		filepath.Join(userRoot, ".ansible", "cp"),
		filepath.Join(userRoot, ".ansible", "roles"),
		filepath.Join(userRoot, ".ansible", "collections"),
	}
	for _, dir := range subdirs {
		if err := os.MkdirAll(dir, 0770); err != nil {
			return fmt.Errorf("creating container user workspace directory %s: %w", dir, err)
		}
	}

	if hasDefaultRange && strings.TrimSpace(userID) != "" {
		if err := validateContainerWorkspaceSlug(userID); err != nil {
			return fmt.Errorf("validating default range directory slug: %w", err)
		}
		rangeDir := filepath.Join(baseDir, "ranges", userID)
		if err := os.MkdirAll(rangeDir, 0770); err != nil {
			return fmt.Errorf("creating default range directory %s: %w", rangeDir, err)
		}
		rangeCfgPath := filepath.Join(rangeDir, "range-config.yml")
		if !FileExists(rangeCfgPath) {
			content := renderDefaultContainerRangeConfig(baseDir, userID)
			if err := os.WriteFile(rangeCfgPath, []byte(content), 0600); err != nil {
				return fmt.Errorf("writing default range config %s: %w", rangeCfgPath, err)
			}
		}
	}

	return nil
}

func renderDefaultContainerRangeConfig(baseDir, userID string) string {
	j2Path := filepath.Join(baseDir, "ansible", "user-management", "templates", "range-config.yml.j2")
	if raw, err := os.ReadFile(j2Path); err == nil && len(raw) > 0 {
		return strings.ReplaceAll(string(raw), "{{ user_id }}", userID)
	}
	examplePath := filepath.Join(baseDir, "ansible", "user-files", "range-config.example.yml")
	if raw, err := os.ReadFile(examplePath); err == nil && len(raw) > 0 {
		return string(raw)
	}
	return defaultContainerRangeConfigYAML(userID)
}

// removeContainerUserWorkspace removes /opt/ludus/users/<username> in pure Go
// when running in container_mode, replacing del-user.yml.
func removeContainerUserWorkspace(extraVars map[string]interface{}) error {
	return removeContainerUserWorkspaceAt(ludusInstallPath, extraVars)
}

func removeContainerUserWorkspaceAt(baseDir string, extraVars map[string]interface{}) error {
	username, _ := extraVars["username"].(string)
	if err := validateContainerWorkspaceSlug(username); err != nil {
		return err
	}
	userRoot := filepath.Join(baseDir, "users", username)
	if err := os.RemoveAll(userRoot); err != nil {
		return fmt.Errorf("removing container user workspace %s: %w", userRoot, err)
	}
	return nil
}
