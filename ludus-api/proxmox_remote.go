package ludusapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
)

// ProxmoxRESTClient is a lightweight HTTPS client for Proxmox VE 8/9 endpoints
// that require ticket + CSRF authentication (such as POST /access/users and
// PUT /access/password, which Proxmox explicitly blocks for API tokens) as well
// as pre-database bootstrap calls prior to PocketBase initialization.
type ProxmoxRESTClient struct {
	BaseURL    string
	HTTPClient *http.Client
	Ticket     string
	CSRFToken  string
	APITokenID string
	APISecret  string
}

type pveEnvelope struct {
	Data   json.RawMessage   `json:"data"`
	Errors map[string]string `json:"errors,omitempty"`
}

func newProxmoxHTTPClient(skipVerify bool) *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipVerify,
			},
		},
	}
}

func normalizeProxmoxAPIBase(rawURL string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(rawURL), "/")
	if strings.HasSuffix(trimmed, "/api2/json") {
		return trimmed
	}
	return trimmed + "/api2/json"
}

// readSecretFileStrict reads a secret file, trimming trailing CR/LF characters.
// On Unix systems when running as root, it rejects group/world-accessible files.
func readSecretFileStrict(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("secret path %s is a directory, expected file", path)
	}
	if runtime.GOOS != "windows" {
		if info.Mode().Perm()&0o077 != 0 {
			return "", fmt.Errorf("secret file %s has overly broad permissions (%#o); expected 0600 or 0400", path, info.Mode().Perm())
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	secret := strings.TrimRight(string(raw), "\r\n")
	if secret == "" {
		return "", fmt.Errorf("secret file %s is empty", path)
	}
	return secret, nil
}

// ResolveProxmoxAdminPassword resolves the Proxmox administrative password used
// for ticket-only endpoints from proxmox_admin_password_file, the default
// /opt/ludus/install/proxmox-admin-password path, or LUDUS_PROXMOX_ADMIN_PASSWORD.
func ResolveProxmoxAdminPassword(cfg *Configuration) (string, error) {
	if cfg != nil && strings.TrimSpace(cfg.ProxmoxAdminPasswordFile) != "" {
		return readSecretFileStrict(strings.TrimSpace(cfg.ProxmoxAdminPasswordFile))
	}
	defaultPath := fmt.Sprintf("%s/install/proxmox-admin-password", ludusInstallPath)
	if FileExists(defaultPath) {
		return readSecretFileStrict(defaultPath)
	}
	if envPw := os.Getenv("LUDUS_PROXMOX_ADMIN_PASSWORD"); envPw != "" {
		return envPw, nil
	}
	return "", errors.New("proxmox admin password unavailable: configure proxmox_admin_password_file (mode 0600) or LUDUS_PROXMOX_ADMIN_PASSWORD")
}

// ResolvePreprovisionedRootToken checks whether an operator supplied an existing
// Proxmox root/admin API token via config or environment variables.
func ResolvePreprovisionedRootToken(cfg *Configuration) (string, string, bool, error) {
	if cfg == nil {
		return "", "", false, nil
	}
	tokenID := strings.TrimSpace(cfg.ProxmoxRootTokenID)
	if tokenID == "" {
		tokenID = strings.TrimSpace(os.Getenv("LUDUS_PROXMOX_ROOT_TOKEN_ID"))
	}
	if tokenID == "" {
		return "", "", false, nil
	}
	if tokenFile := strings.TrimSpace(cfg.ProxmoxRootTokenFile); tokenFile != "" {
		secret, err := readSecretFileStrict(tokenFile)
		if err != nil {
			return "", "", false, fmt.Errorf("reading proxmox_root_token_file: %w", err)
		}
		return tokenID, secret, true, nil
	}
	if envSecret := strings.TrimSpace(os.Getenv("LUDUS_PROXMOX_ROOT_TOKEN_SECRET")); envSecret != "" {
		return tokenID, envSecret, true, nil
	}
	return "", "", false, fmt.Errorf("proxmox_root_token_id (%s) is set, but proxmox_root_token_file / LUDUS_PROXMOX_ROOT_TOKEN_SECRET is missing", tokenID)
}

// NewProxmoxTicketClient authenticates against POST /api2/json/access/ticket with
// username (including @realm) and password, returning a session-backed REST client.
func NewProxmoxTicketClient(ctx context.Context, rawProxmoxURL string, skipVerify bool, userID string, password string) (*ProxmoxRESTClient, error) {
	baseURL := normalizeProxmoxAPIBase(rawProxmoxURL)
	httpClient := newProxmoxHTTPClient(skipVerify)

	form := url.Values{}
	form.Set("username", userID)
	form.Set("password", password)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/access/ticket", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("building Proxmox ticket request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connecting to Proxmox API (%s): %w", baseURL, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("proxmox ticket authentication failed for %s (HTTP %d): %s", userID, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var env struct {
		Data struct {
			Ticket              string `json:"ticket"`
			CSRFPreventionToken string `json:"CSRFPreventionToken"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("decoding Proxmox ticket response: %w", err)
	}
	if env.Data.Ticket == "" || env.Data.CSRFPreventionToken == "" {
		return nil, fmt.Errorf("proxmox ticket response for %s missing ticket or CSRFPreventionToken", userID)
	}

	return &ProxmoxRESTClient{
		BaseURL:    baseURL,
		HTTPClient: httpClient,
		Ticket:     env.Data.Ticket,
		CSRFToken:  env.Data.CSRFPreventionToken,
	}, nil
}

// NewProxmoxAPITokenClient creates a REST client authenticated with a Proxmox API token.
func NewProxmoxAPITokenClient(rawProxmoxURL string, skipVerify bool, tokenID, tokenSecret string) *ProxmoxRESTClient {
	return &ProxmoxRESTClient{
		BaseURL:    normalizeProxmoxAPIBase(rawProxmoxURL),
		HTTPClient: newProxmoxHTTPClient(skipVerify),
		APITokenID: tokenID,
		APISecret:  tokenSecret,
	}
}

// NewProxmoxAdminTicketClient opens a ticket-authenticated Proxmox REST session using
// the configured administrative principal and password file.
func NewProxmoxAdminTicketClient(ctx context.Context, cfg *Configuration) (*ProxmoxRESTClient, error) {
	if cfg == nil {
		cfg = &ServerConfiguration
	}
	adminPw, err := ResolveProxmoxAdminPassword(cfg)
	if err != nil {
		return nil, err
	}
	return NewProxmoxTicketClient(ctx, cfg.ProxmoxURL, cfg.ProxmoxInvalidCert, cfg.EffectiveProxmoxAdminUser(), adminPw)
}

// NewProxmoxBestEffortAdminClient opens an admin ticket client if admin password credentials
// are available, or falls back to a pre-provisioned / PocketBase root API token client for
// endpoints that accept API tokens.
func NewProxmoxBestEffortAdminClient(ctx context.Context, cfg *Configuration) (*ProxmoxRESTClient, error) {
	if cfg == nil {
		cfg = &ServerConfiguration
	}
	if client, err := NewProxmoxAdminTicketClient(ctx, cfg); err == nil {
		return client, nil
	}
	if tokenID, secret, ok, err := ResolvePreprovisionedRootToken(cfg); err != nil {
		return nil, err
	} else if ok {
		return NewProxmoxAPITokenClient(cfg.ProxmoxURL, cfg.ProxmoxInvalidCert, tokenID, secret), nil
	}
	if app != nil {
		if rootRecord, err := app.FindFirstRecordByData("users", "userID", "ROOT"); err == nil && rootRecord != nil {
			tokenID := rootRecord.GetString("proxmoxTokenID")
			encSecret := rootRecord.GetString("proxmoxTokenSecret")
			if tokenID != "" && encSecret != "" {
				if secret, decErr := DecryptStringFromDatabase(encSecret); decErr == nil {
					return NewProxmoxAPITokenClient(cfg.ProxmoxURL, cfg.ProxmoxInvalidCert, tokenID, secret), nil
				}
			}
		}
	}
	return nil, errors.New("no Proxmox admin credentials available (configure proxmox_admin_password_file or proxmox_root_token_id/proxmox_root_token_file)")
}

// Do executes an authenticated Proxmox REST API call and optionally decodes response.data into out.
func (c *ProxmoxRESTClient) Do(ctx context.Context, method, apiPath string, form url.Values, out interface{}) error {
	if !strings.HasPrefix(apiPath, "/") {
		apiPath = "/" + apiPath
	}
	fullURL := c.BaseURL + apiPath

	var bodyReader io.Reader
	if form != nil {
		encoded := form.Encode()
		if method == http.MethodGet || method == http.MethodDelete {
			if encoded != "" {
				fullURL += "?" + encoded
			}
		} else {
			bodyReader = strings.NewReader(encoded)
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return fmt.Errorf("building %s %s request: %w", method, apiPath, err)
	}
	if bodyReader != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if c.APITokenID != "" && c.APISecret != "" {
		req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", c.APITokenID, c.APISecret))
	} else if c.Ticket != "" {
		req.Header.Set("Cookie", "PVEAuthCookie="+c.Ticket)
		if method != http.MethodGet && method != http.MethodHead {
			req.Header.Set("CSRFPreventionToken", c.CSRFToken)
		}
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("proxmox %s %s failed: %w", method, apiPath, err)
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errEnv pveEnvelope
		if json.Unmarshal(respBytes, &errEnv) == nil && len(errEnv.Errors) > 0 {
			return fmt.Errorf("proxmox %s %s returned HTTP %d: %v (%s)", method, apiPath, resp.StatusCode, errEnv.Errors, strings.TrimSpace(resp.Status))
		}
		return fmt.Errorf("proxmox %s %s returned HTTP %d: %s", method, apiPath, resp.StatusCode, strings.TrimSpace(string(respBytes)))
	}

	if out != nil && len(respBytes) > 0 {
		var env pveEnvelope
		if err := json.Unmarshal(respBytes, &env); err != nil {
			return fmt.Errorf("decoding Proxmox response from %s %s: %w", method, apiPath, err)
		}
		if len(env.Data) > 0 && string(env.Data) != "null" {
			if err := json.Unmarshal(env.Data, out); err != nil {
				return fmt.Errorf("decoding Proxmox data payload from %s %s: %w", method, apiPath, err)
			}
		}
	}
	return nil
}

// Get executes an authenticated HTTP GET against the Proxmox REST API and decodes response.data into out.
func (c *ProxmoxRESTClient) Get(ctx context.Context, apiPath string, out interface{}) error {
	return c.Do(ctx, http.MethodGet, apiPath, nil, out)
}

// GetRemoteProxmoxVersion queries GET /api2/json/version on the configured Proxmox host.
func GetRemoteProxmoxVersion(ctx context.Context, cfg *Configuration) (string, error) {
	client, err := NewProxmoxBestEffortAdminClient(ctx, cfg)
	if err != nil {
		return "", err
	}
	var ver struct {
		Version string `json:"version"`
		Release string `json:"release"`
	}
	if err := client.Do(ctx, http.MethodGet, "/version", nil, &ver); err != nil {
		return "", err
	}
	if ver.Version != "" {
		return ver.Version, nil
	}
	return ver.Release, nil
}

// IsRemoteProxmoxCluster queries GET /api2/json/cluster/status (falling back to /nodes)
// to determine whether the remote Proxmox endpoint has multiple cluster nodes.
func IsRemoteProxmoxCluster(ctx context.Context, cfg *Configuration) (bool, error) {
	client, err := NewProxmoxBestEffortAdminClient(ctx, cfg)
	if err != nil {
		return false, err
	}
	var statusEntries []struct {
		Type string `json:"type"`
		Name string `json:"name"`
	}
	if err := client.Do(ctx, http.MethodGet, "/cluster/status", nil, &statusEntries); err == nil && len(statusEntries) > 0 {
		nodeCount := 0
		for _, entry := range statusEntries {
			if entry.Type == "node" {
				nodeCount++
			}
		}
		return nodeCount > 1, nil
	}

	var nodes []struct {
		Node string `json:"node"`
	}
	if err := client.Do(ctx, http.MethodGet, "/nodes", nil, &nodes); err != nil {
		return false, err
	}
	return len(nodes) > 1, nil
}

// createRootAPITokenViaAPI creates (or rotates if already present) the unseparated
// ludus-token on the Proxmox admin account using HTTPS, or returns a validated
// pre-provisioned root token if configured.
func createRootAPITokenViaAPI(cfg *Configuration) (string, string, error) {
	ctx := context.Background()
	if cfg == nil {
		cfg = &ServerConfiguration
	}

	if tokenID, tokenSecret, ok, err := ResolvePreprovisionedRootToken(cfg); err != nil {
		return "", "", err
	} else if ok {
		tokenClient := NewProxmoxAPITokenClient(cfg.ProxmoxURL, cfg.ProxmoxInvalidCert, tokenID, tokenSecret)
		var ver map[string]interface{}
		if err := tokenClient.Do(ctx, http.MethodGet, "/version", nil, &ver); err != nil {
			return "", "", fmt.Errorf("validating pre-provisioned proxmox_root_token_id %s: %w", tokenID, err)
		}
		return tokenID, tokenSecret, nil
	}

	client, err := NewProxmoxAdminTicketClient(ctx, cfg)
	if err != nil {
		return "", "", err
	}

	adminUserID := cfg.EffectiveProxmoxAdminUser()
	tokenPath := fmt.Sprintf("/access/users/%s/token/ludus-token", url.PathEscape(adminUserID))
	form := url.Values{}
	form.Set("privsep", "0")
	form.Set("comment", "Ludus Token - Do not modify or delete")

	type tokenCreateResp struct {
		FullTokenID string `json:"full-tokenid"`
		Value       string `json:"value"`
	}
	var created tokenCreateResp
	err = client.Do(ctx, http.MethodPost, tokenPath, form, &created)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "already exists") || strings.Contains(err.Error(), "400") {
			_ = client.Do(ctx, http.MethodDelete, tokenPath, nil, nil)
			err = client.Do(ctx, http.MethodPost, tokenPath, form, &created)
		}
		if err != nil {
			return "", "", fmt.Errorf("creating Proxmox API token via HTTPS for %s: %w", adminUserID, err)
		}
	}
	if created.FullTokenID == "" {
		created.FullTokenID = adminUserID + "!ludus-token"
	}
	if created.Value == "" {
		return "", "", fmt.Errorf("proxmox returned empty token secret for %s", created.FullTokenID)
	}
	return created.FullTokenID, created.Value, nil
}

// setProxmoxPasswordViaAPI updates a user's password via PUT /api2/json/access/password
// using an admin ticket (or self-ticket fallback when oldPassword is supplied).
func setProxmoxPasswordViaAPI(cfg *Configuration, username, realm, newPassword, oldPassword string) error {
	ctx := context.Background()
	if cfg == nil {
		cfg = &ServerConfiguration
	}
	fullUserID := username + "@" + realm

	client, err := NewProxmoxAdminTicketClient(ctx, cfg)
	if err != nil && oldPassword != "" {
		client, err = NewProxmoxTicketClient(ctx, cfg.ProxmoxURL, cfg.ProxmoxInvalidCert, fullUserID, oldPassword)
	}
	if err != nil {
		return fmt.Errorf("obtaining Proxmox ticket to set password for %s: %w", fullUserID, err)
	}

	form := url.Values{}
	form.Set("userid", fullUserID)
	form.Set("password", newPassword)
	if err := client.Do(ctx, http.MethodPut, "/access/password", form, nil); err != nil {
		return fmt.Errorf("updating Proxmox password for %s: %w", fullUserID, err)
	}
	return nil
}

// createProxmoxUserAPITokenViaAPI authenticates as username@realm (falling back to admin
// ticket if needed) and creates or rotates the unseparated 'ludus-token' over HTTPS.
func createProxmoxUserAPITokenViaAPI(cfg *Configuration, username, realm, userPassword string) (string, string, error) {
	ctx := context.Background()
	if cfg == nil {
		cfg = &ServerConfiguration
	}
	fullUserID := username + "@" + realm

	var client *ProxmoxRESTClient
	var err error
	if userPassword != "" {
		client, err = NewProxmoxTicketClient(ctx, cfg.ProxmoxURL, cfg.ProxmoxInvalidCert, fullUserID, userPassword)
	}
	if err != nil || client == nil {
		adminClient, adminErr := NewProxmoxBestEffortAdminClient(ctx, cfg)
		if adminErr != nil {
			if err != nil {
				return "", "", err
			}
			return "", "", adminErr
		}
		client = adminClient
	}

	tokenPath := fmt.Sprintf("/access/users/%s/token/ludus-token", url.PathEscape(fullUserID))
	form := url.Values{}
	form.Set("privsep", "0")
	form.Set("comment", "Ludus Token - Do not modify or delete")

	type tokenCreateResp struct {
		FullTokenID string `json:"full-tokenid"`
		Value       string `json:"value"`
	}
	var created tokenCreateResp
	err = client.Do(ctx, http.MethodPost, tokenPath, form, &created)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "already exists") || strings.Contains(err.Error(), "400") {
			if delErr := client.Do(ctx, http.MethodDelete, tokenPath, nil, nil); delErr != nil {
				_ = deleteProxmoxUserTokenViaAPI(ctx, cfg, username, realm, "ludus-token")
			}
			err = client.Do(ctx, http.MethodPost, tokenPath, form, &created)
		}
		if err != nil {
			return "", "", fmt.Errorf("creating Proxmox API token for %s: %w", fullUserID, err)
		}
	}
	if created.FullTokenID == "" {
		created.FullTokenID = fullUserID + "!ludus-token"
	}
	if created.Value == "" {
		return "", "", fmt.Errorf("proxmox returned empty API token value for %s", created.FullTokenID)
	}
	return created.FullTokenID, created.Value, nil
}

// deleteProxmoxUserTokenViaAPI deletes an existing user API token over HTTPS without pveum.
func deleteProxmoxUserTokenViaAPI(ctx context.Context, cfg *Configuration, username, realm, tokenName string) error {
	if cfg == nil {
		cfg = &ServerConfiguration
	}
	fullUserID := username + "@" + realm
	tokenPath := fmt.Sprintf("/access/users/%s/token/%s", url.PathEscape(fullUserID), url.PathEscape(tokenName))

	if rootClient, err := GetRootGoProxmoxClient(); err == nil && rootClient != nil {
		var out interface{}
		if delErr := rootClient.Delete(ctx, tokenPath, &out); delErr == nil {
			return nil
		}
	}

	adminClient, err := NewProxmoxBestEffortAdminClient(ctx, cfg)
	if err != nil {
		return err
	}
	return adminClient.Do(ctx, http.MethodDelete, tokenPath, nil, nil)
}

// ensureProxmoxUserAndACLsViaAPI provisions or updates a Ludus user in Proxmox (e.g., in the
// built-in @pve realm) along with group memberships and pool/datastore ACLs, replacing the
// five local pveum tasks in add-user.yml when running in RemoteProxmox VM mode.
func ensureProxmoxUserAndACLsViaAPI(cfg *Configuration, username, realm, password, userID string, isAdmin, hasDefaultRange bool) error {
	ctx := context.Background()
	if cfg == nil {
		cfg = &ServerConfiguration
	}
	fullUserID := username + "@" + realm

	ticketClient, err := NewProxmoxAdminTicketClient(ctx, cfg)
	if err != nil {
		return fmt.Errorf("proxmox admin ticket required to provision %s: %w", fullUserID, err)
	}

	groups := []string{"ludus_users"}
	if isAdmin {
		groups = append(groups, "ludus_admins")
	}
	groupsCSV := strings.Join(groups, ",")

	userPath := fmt.Sprintf("/access/users/%s", url.PathEscape(fullUserID))
	var existing map[string]interface{}
	if getErr := ticketClient.Do(ctx, http.MethodGet, userPath, nil, &existing); getErr != nil {
		createForm := url.Values{}
		createForm.Set("userid", fullUserID)
		createForm.Set("groups", groupsCSV)
		createForm.Set("enable", "1")
		if realm == "pve" && password != "" {
			createForm.Set("password", password)
		}
		if err := ticketClient.Do(ctx, http.MethodPost, "/access/users", createForm, nil); err != nil {
			return fmt.Errorf("creating Proxmox user %s: %w", fullUserID, err)
		}
	} else {
		updateForm := url.Values{}
		updateForm.Set("groups", groupsCSV)
		updateForm.Set("enable", "1")
		if err := ticketClient.Do(ctx, http.MethodPut, userPath, updateForm, nil); err != nil {
			return fmt.Errorf("updating Proxmox user %s groups: %w", fullUserID, err)
		}
	}

	// Explicitly set/verify password via /access/password so existing @pve users or Proxmox
	// versions that ignore password on user update always match the Ludus DB password.
	if password != "" {
		pwForm := url.Values{}
		pwForm.Set("userid", fullUserID)
		pwForm.Set("password", password)
		if err := ticketClient.Do(ctx, http.MethodPut, "/access/password", pwForm, nil); err != nil {
			return fmt.Errorf("setting Proxmox password for %s: %w", fullUserID, err)
		}
	}

	// Pool ACLs for default range (matches add-user.yml)
	if hasDefaultRange && userID != "" {
		for _, role := range []string{"PVEAdmin", "PVESDNAdmin"} {
			if err := putProxmoxACL(ctx, ticketClient, "/pool/"+userID, fullUserID, "", role); err != nil {
				return err
			}
			if err := putProxmoxACL(ctx, ticketClient, "/pool/"+userID, "", "ludus_admins", role); err != nil {
				return err
			}
		}
	}

	// Datastore ACLs on configured VM & ISO storage pools (fixes upstream hardcoded /storage/local)
	storagePools := uniqueNonEmptyStrings(cfg.ProxmoxVMStoragePool, cfg.ProxmoxISOStoragePool)
	for _, pool := range storagePools {
		if err := putProxmoxACL(ctx, ticketClient, "/storage/"+pool, fullUserID, "", "PVEDatastoreAdmin"); err != nil {
			return err
		}
	}
	// Best-effort grant on /storage/local if present and distinct
	if !containsString(storagePools, "local") {
		_ = putProxmoxACL(ctx, ticketClient, "/storage/local", fullUserID, "", "PVEDatastoreAdmin")
	}

	return nil
}

func putProxmoxACL(ctx context.Context, client *ProxmoxRESTClient, aclPath, users, groups, roles string) error {
	form := url.Values{}
	form.Set("path", aclPath)
	form.Set("roles", roles)
	form.Set("propagate", "1")
	if users != "" {
		form.Set("users", users)
	}
	if groups != "" {
		form.Set("groups", groups)
	}
	if err := client.Do(ctx, http.MethodPut, "/access/acl", form, nil); err != nil {
		return fmt.Errorf("setting Proxmox ACL on %s (users=%q groups=%q roles=%q): %w", aclPath, users, groups, roles, err)
	}
	return nil
}

func uniqueNonEmptyStrings(values ...string) []string {
	var out []string
	for _, v := range values {
		trimmed := strings.TrimSpace(v)
		if trimmed != "" && !containsString(out, trimmed) {
			out = append(out, trimmed)
		}
	}
	return out
}

func containsString(slice []string, target string) bool {
	for _, item := range slice {
		if item == target {
			return true
		}
	}
	return false
}
