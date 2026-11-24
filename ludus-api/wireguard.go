package ludusapi

import (
	"bytes"
	"fmt"
	"ludusapi/models"
	"os"
	"strings"
	"text/template"
)

const userWireGuardConfigTemplate = `[Interface]
PrivateKey = {{ .client_private_key }}
Address = 198.51.100.{{ .user_number }}/32

[Peer]
PublicKey = {{ .server_public_key }}
Endpoint = {{ .endpoint }}
AllowedIPs = {{ .allowed_ips }}
PersistentKeepalive = 25
`

func resolveWireGuardKeyMaterialForUser(user *models.User) (clientPrivateKey string, serverPublicKey string, endpoint string, err error) {
	if poolPath := EffectiveWireGuardPoolPath(); poolPath != "" {
		pool, err := LoadWireGuardClientPool(poolPath)
		if err != nil {
			return "", "", "", err
		}
		priv, err := pool.DeriveClientPrivateKey(user.UserNumber())
		if err != nil {
			return "", "", "", err
		}
		ep := strings.TrimSpace(pool.Endpoint)
		if ep == "" {
			host := strings.TrimSpace(ServerConfiguration.EdgeVMIP)
			if host == "" {
				host = strings.TrimSpace(ServerConfiguration.ProxmoxPublicIP)
			}
			port := pool.ListenPort
			if ServerConfiguration.WireguardPort > 0 {
				port = ServerConfiguration.WireguardPort
			}
			ep = fmt.Sprintf("%s:%d", host, port)
		}
		return priv, strings.TrimSpace(pool.ServerPublicKey), ep, nil
	}

	if IsContainerMode() {
		return "", "", "", fmt.Errorf("WireGuard pool is not initialized yet (set wireguard_pool_file or enable edge_auto_provision)")
	}

	serverPubBytes, err := os.ReadFile("/etc/wireguard/server-public-key")
	if err != nil {
		return "", "", "", err
	}
	clientPrivBytes, err := os.ReadFile(fmt.Sprintf("/etc/wireguard/%s-client-private-key", user.UserId()))
	if err != nil {
		return "", "", "", err
	}
	return strings.TrimSpace(string(clientPrivBytes)),
		strings.TrimSpace(string(serverPubBytes)),
		fmt.Sprintf("%s:%d", ServerConfiguration.ProxmoxPublicIP, ServerConfiguration.WireguardPort),
		nil
}

func getWireGuardConfigForUser(user *models.User) (string, error) {
	clientPrivateKey, serverPublicKey, endpoint, err := resolveWireGuardKeyMaterialForUser(user)
	if err != nil {
		return "", err
	}

	// Render the template
	template, err := template.New("userWireGuardConfigTemplate").Parse(userWireGuardConfigTemplate)
	if err != nil {
		return "", err
	}

	allowedIPs, err := createAllowedIPsStringForUser(user)
	if err != nil {
		return "", err
	}

	var result bytes.Buffer
	if err := template.Execute(&result, map[string]interface{}{
		"client_private_key": clientPrivateKey,
		"server_public_key":  serverPublicKey,
		"endpoint":           endpoint,
		"user_number":        user.UserNumber(),
		"allowed_ips":        allowedIPs,
	}); err != nil {
		return "", err
	}

	return result.String(), nil
}

func createAllowedIPsStringForUser(user *models.User) (string, error) {
	elements := []string{
		"198.51.100.1/32", // Allow access to the server
	}

	accessibleRanges, err := GetAccessibleRangesForUser(user)
	if err != nil {
		return "", err
	}

	for _, rangeAccessibleObject := range accessibleRanges {
		elements = append(elements, fmt.Sprintf("10.%d.0.0/16", rangeAccessibleObject.RangeNumber))
	}

	return strings.Join(elements, ","), nil
}
