package ludusapi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"ludusapi/dto"
	"ludusapi/models"
	"math/big"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/security"
)

const oidcProviderName = "oidc"

var (
	errOIDCGroupForbidden      = errors.New("your OIDC account is not a member of any allowed Ludus group")
	errSSOExistingUserRequired = errors.New(ssoExistingUserRequiredMessage)
)

// OIDCDiscoveryDocument holds standard OpenID Connect Discovery 1.0 metadata.
type OIDCDiscoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// OIDCVerifiedIdentity holds cryptographically verified OIDC user claims.
type OIDCVerifiedIdentity struct {
	Subject   string
	Email     string
	Name      string
	Username  string
	Groups    []string
	RawClaims map[string]any
}

type jwksCacheEntry struct {
	disc        OIDCDiscoveryDocument
	keysByID    map[string]crypto.PublicKey
	defaultKey  crypto.PublicKey
	fetchedAt   time.Time
	lastRefresh time.Time
}

var (
	globalJWKSMu    sync.Mutex
	globalJWKSCache = make(map[string]*jwksCacheEntry)
)

// ResetOIDCCache clears the in-memory OIDC discovery/JWKS cache (used by tests and config reloads).
func ResetOIDCCache() {
	globalJWKSMu.Lock()
	globalJWKSCache = make(map[string]*jwksCacheEntry)
	globalJWKSMu.Unlock()
}

func newOIDCHTTPClient(skipTLSVerify bool) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: skipTLSVerify,
			},
		},
	}
}

// DiscoverOIDCConfiguration fetches <issuerURL>/.well-known/openid-configuration.
func DiscoverOIDCConfiguration(ctx context.Context, issuerURL string, skipTLSVerify bool) (*OIDCDiscoveryDocument, error) {
	issuer := strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	if issuer == "" {
		return nil, fmt.Errorf("oidc_issuer_url is empty")
	}
	wellKnownURL := issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating OIDC discovery request: %w", err)
	}
	resp, err := newOIDCHTTPClient(skipTLSVerify).Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching OIDC discovery %s: %w", wellKnownURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading OIDC discovery %s: %w", wellKnownURL, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery %s returned HTTP %d: %s", wellKnownURL, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var doc OIDCDiscoveryDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decoding OIDC discovery %s: %w", wellKnownURL, err)
	}
	if strings.TrimSpace(doc.Issuer) == "" {
		doc.Issuer = issuer
	}
	if strings.TrimSpace(doc.AuthorizationEndpoint) == "" || strings.TrimSpace(doc.TokenEndpoint) == "" || strings.TrimSpace(doc.JWKSURI) == "" {
		return nil, fmt.Errorf("OIDC discovery %s missing required endpoints", wellKnownURL)
	}
	return &doc, nil
}

// FallbackKeycloakDiscovery derives standard Keycloak OIDC URLs if Keycloak is still starting during Ludus boot.
func FallbackKeycloakDiscovery(issuerURL string) OIDCDiscoveryDocument {
	issuer := strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	base := issuer + "/protocol/openid-connect"
	return OIDCDiscoveryDocument{
		Issuer:                issuer,
		AuthorizationEndpoint: base + "/auth",
		TokenEndpoint:         base + "/token",
		UserInfoEndpoint:      base + "/userinfo",
		JWKSURI:               base + "/certs",
	}
}

// ResolveOIDCClientSecret loads the OIDC client secret from oidc_client_secret_file or LUDUS_OIDC_CLIENT_SECRET.
func ResolveOIDCClientSecret(cfg *Configuration) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("nil configuration")
	}
	secretFile := strings.TrimSpace(cfg.OIDCClientSecretFile)
	if envFile := strings.TrimSpace(os.Getenv("LUDUS_OIDC_CLIENT_SECRET_FILE")); envFile != "" {
		secretFile = envFile
	}
	if secretFile != "" {
		return readSecretFile(secretFile, cfg.ContainerMode)
	}
	if envSecret := strings.TrimSpace(os.Getenv("LUDUS_OIDC_CLIENT_SECRET")); envSecret != "" {
		return envSecret, nil
	}
	return "", fmt.Errorf("oidc_client_secret_file (or LUDUS_OIDC_CLIENT_SECRET) is required when oidc_enabled is true")
}

// ReconcileDeclarativeOIDCProvider idempotently configures PocketBase's users collection OIDC provider from config.yml.
func ReconcileDeclarativeOIDCProvider(ctx context.Context, pbApp core.App, cfg *Configuration) error {
	if cfg == nil || !cfg.OIDCEnabled {
		return nil
	}
	issuer := strings.TrimRight(strings.TrimSpace(cfg.OIDCIssuerURL), "/")
	clientID := strings.TrimSpace(cfg.OIDCClientID)
	if issuer == "" || clientID == "" {
		return fmt.Errorf("oidc_issuer_url and oidc_client_id are required when oidc_enabled is true")
	}
	clientSecret, err := ResolveOIDCClientSecret(cfg)
	if err != nil {
		return err
	}

	discPtr, discErr := DiscoverOIDCConfiguration(ctx, issuer, cfg.OIDCSkipTLSVerify)
	var disc OIDCDiscoveryDocument
	if discErr != nil {
		if logger != nil {
			logger.Warn(fmt.Sprintf("OIDC discovery failed during startup (%v); seeding standard Keycloak OIDC endpoints for %s", discErr, issuer))
		}
		disc = FallbackKeycloakDiscovery(issuer)
	} else {
		disc = *discPtr
	}

	collection, err := pbApp.FindCollectionByNameOrId("users")
	if err != nil {
		return fmt.Errorf("finding users collection for OIDC bootstrap: %w", err)
	}

	displayName := strings.TrimSpace(cfg.OIDCDisplayName)
	if displayName == "" {
		displayName = "SSO"
	}
	pkce := true
	desired := core.OAuth2ProviderConfig{
		Name:         oidcProviderName,
		DisplayName:  displayName,
		ClientId:     clientID,
		ClientSecret: clientSecret,
		AuthURL:      disc.AuthorizationEndpoint,
		TokenURL:     disc.TokenEndpoint,
		UserInfoURL:  disc.UserInfoEndpoint,
		PKCE:         &pkce,
		Extra: map[string]any{
			"jwksURL": disc.JWKSURI,
			"issuers": []string{disc.Issuer},
		},
	}

	updated := false
	providers := make([]core.OAuth2ProviderConfig, 0, len(collection.OAuth2.Providers)+1)
	for _, existing := range collection.OAuth2.Providers {
		if existing.Name == oidcProviderName {
			providers = append(providers, desired)
			updated = true
		} else {
			providers = append(providers, existing)
		}
	}
	if !updated {
		providers = append(providers, desired)
	}
	collection.OAuth2.Enabled = true
	collection.OAuth2.Providers = providers

	if err := pbApp.Save(collection); err != nil {
		return fmt.Errorf("saving users collection OIDC configuration: %w", err)
	}
	return nil
}

func normalizeOIDCGroupName(raw string) string {
	return strings.TrimPrefix(strings.TrimSpace(raw), "/")
}

func appendClaimStrings(dst []string, seen map[string]struct{}, val any) []string {
	switch v := val.(type) {
	case []string:
		for _, item := range v {
			norm := normalizeOIDCGroupName(item)
			if norm == "" {
				continue
			}
			if _, ok := seen[norm]; !ok {
				seen[norm] = struct{}{}
				dst = append(dst, norm)
			}
		}
	case []any:
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				continue
			}
			norm := normalizeOIDCGroupName(s)
			if norm == "" {
				continue
			}
			if _, exists := seen[norm]; !exists {
				seen[norm] = struct{}{}
				dst = append(dst, norm)
			}
		}
	case string:
		for _, part := range strings.Fields(v) {
			norm := normalizeOIDCGroupName(part)
			if norm == "" {
				continue
			}
			if _, ok := seen[norm]; !ok {
				seen[norm] = struct{}{}
				dst = append(dst, norm)
			}
		}
	}
	return dst
}

// ExtractOIDCGroups extracts normalized group/role names from Keycloak/OIDC claims
// ("groups", "roles", and "realm_access.roles"), stripping leading "/" paths.
func ExtractOIDCGroups(rawClaims map[string]any) []string {
	if len(rawClaims) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, 8)
	var out []string
	out = appendClaimStrings(out, seen, rawClaims["groups"])
	out = appendClaimStrings(out, seen, rawClaims["roles"])
	if realmAccess, ok := rawClaims["realm_access"].(map[string]any); ok {
		out = appendClaimStrings(out, seen, realmAccess["roles"])
	}
	return out
}

// EvaluateOIDCGroupAccess enforces oidc_allowed_groups (when non-empty; oidc_admin_groups are
// implicitly permitted) and computes isAdmin from oidc_admin_groups.
func EvaluateOIDCGroupAccess(rawClaims map[string]any, allowedGroups []string, adminGroups []string) (allowed bool, isAdmin bool, groups []string) {
	groups = ExtractOIDCGroups(rawClaims)

	adminSet := make(map[string]struct{}, len(adminGroups))
	for _, g := range adminGroups {
		if norm := normalizeOIDCGroupName(g); norm != "" {
			adminSet[norm] = struct{}{}
		}
	}
	for _, g := range groups {
		if _, ok := adminSet[g]; ok {
			isAdmin = true
			break
		}
	}

	allowSet := make(map[string]struct{}, len(allowedGroups)+len(adminSet))
	for _, g := range allowedGroups {
		if norm := normalizeOIDCGroupName(g); norm != "" {
			allowSet[norm] = struct{}{}
		}
	}
	if len(allowSet) == 0 {
		return true, isAdmin, groups
	}
	// Members of oidc_admin_groups are always permitted even if omitted from oidc_allowed_groups.
	for g := range adminSet {
		allowSet[g] = struct{}{}
	}
	for _, g := range groups {
		if _, ok := allowSet[g]; ok {
			return true, isAdmin, groups
		}
	}
	return false, false, groups
}

type jwkJSON struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwksDocumentJSON struct {
	Keys []jwkJSON `json:"keys"`
}

func parseJWKPublicKey(k jwkJSON) (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("decoding RSA n: %w", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("decoding RSA e: %w", err)
		}
		eBig := new(big.Int).SetBytes(eBytes)
		if !eBig.IsInt64() || eBig.Int64() <= 1 {
			return nil, fmt.Errorf("invalid RSA exponent")
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(eBig.Int64()),
		}, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve %q", k.Crv)
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("decoding EC x: %w", err)
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, fmt.Errorf("decoding EC y: %w", err)
		}
		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}, nil
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("unsupported OKP curve %q", k.Crv)
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(xBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid Ed25519 public key")
		}
		return ed25519.PublicKey(xBytes), nil
	default:
		return nil, fmt.Errorf("unsupported JWK kty %q", k.Kty)
	}
}

func getOrRefreshJWKS(ctx context.Context, issuerURL string, skipTLSVerify bool, forceRefresh bool) (*jwksCacheEntry, error) {
	issuer := strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	now := time.Now()

	globalJWKSMu.Lock()
	cached := globalJWKSCache[issuer]
	if cached != nil && !forceRefresh && now.Sub(cached.fetchedAt) < 5*time.Minute {
		entryCopy := *cached
		globalJWKSMu.Unlock()
		return &entryCopy, nil
	}
	if cached != nil && forceRefresh && now.Sub(cached.lastRefresh) < 5*time.Second {
		entryCopy := *cached
		globalJWKSMu.Unlock()
		return &entryCopy, nil
	}
	globalJWKSMu.Unlock()

	disc, err := DiscoverOIDCConfiguration(ctx, issuer, skipTLSVerify)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, disc.JWKSURI, nil)
	if err != nil {
		return nil, fmt.Errorf("creating JWKS request: %w", err)
	}
	resp, err := newOIDCHTTPClient(skipTLSVerify).Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS %s: %w", disc.JWKSURI, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading JWKS %s: %w", disc.JWKSURI, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS %s returned HTTP %d", disc.JWKSURI, resp.StatusCode)
	}
	var doc jwksDocumentJSON
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decoding JWKS %s: %w", disc.JWKSURI, err)
	}

	keysByID := make(map[string]crypto.PublicKey, len(doc.Keys))
	var defaultKey crypto.PublicKey
	for _, k := range doc.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, parseErr := parseJWKPublicKey(k)
		if parseErr != nil {
			continue
		}
		if k.Kid != "" {
			keysByID[k.Kid] = pub
		}
		if defaultKey == nil {
			defaultKey = pub
		}
	}
	if len(keysByID) == 0 && defaultKey == nil {
		return nil, fmt.Errorf("JWKS %s contained no usable signing keys", disc.JWKSURI)
	}

	entry := &jwksCacheEntry{
		disc:        *disc,
		keysByID:    keysByID,
		defaultKey:  defaultKey,
		fetchedAt:   now,
		lastRefresh: now,
	}
	globalJWKSMu.Lock()
	globalJWKSCache[issuer] = entry
	entryCopy := *entry
	globalJWKSMu.Unlock()
	return &entryCopy, nil
}

func tokenMatchesAllowedAudience(claims jwt.MapClaims, allowedAudiences []string) bool {
	if len(allowedAudiences) == 0 {
		return false
	}
	allowSet := make(map[string]struct{}, len(allowedAudiences))
	for _, a := range allowedAudiences {
		if trimmed := strings.TrimSpace(a); trimmed != "" {
			allowSet[trimmed] = struct{}{}
		}
	}
	if audList, err := claims.GetAudience(); err == nil {
		for _, aud := range audList {
			if _, ok := allowSet[strings.TrimSpace(aud)]; ok {
				return true
			}
		}
	}
	// Keycloak access tokens frequently set aud="account" and carry the OIDC client ID in azp.
	if azp, ok := claims["azp"].(string); ok {
		if _, match := allowSet[strings.TrimSpace(azp)]; match {
			return true
		}
	}
	return false
}

// VerifyOIDCToken cryptographically validates a Keycloak/OIDC ID or Access token against the
// configured issuer's JWKS, verifies issuer/audience/expiration, and optionally enriches missing
// email/group claims from the OIDC userinfo endpoint when optionalAccessToken is provided.
func VerifyOIDCToken(ctx context.Context, cfg *Configuration, rawToken string, optionalAccessToken string) (*OIDCVerifiedIdentity, error) {
	if cfg == nil || !cfg.OIDCEnabled {
		return nil, fmt.Errorf("OIDC authentication is not enabled")
	}
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil, fmt.Errorf("missing OIDC token")
	}

	entry, err := getOrRefreshJWKS(ctx, cfg.OIDCIssuerURL, cfg.OIDCSkipTLSVerify, false)
	if err != nil {
		return nil, err
	}

	allowedMethods := []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"}
	parseWithEntry := func(e *jwksCacheEntry) (*jwt.Token, jwt.MapClaims, error) {
		claims := jwt.MapClaims{}
		tok, pErr := jwt.ParseWithClaims(rawToken, claims, func(t *jwt.Token) (any, error) {
			kid, _ := t.Header["kid"].(string)
			if kid != "" {
				if key, ok := e.keysByID[kid]; ok {
					return key, nil
				}
				return nil, fmt.Errorf("unknown JWK kid %q", kid)
			}
			if e.defaultKey != nil {
				return e.defaultKey, nil
			}
			return nil, fmt.Errorf("missing JWK kid header")
		},
			jwt.WithValidMethods(allowedMethods),
			jwt.WithIssuer(e.disc.Issuer),
			jwt.WithExpirationRequired(),
			jwt.WithLeeway(30*time.Second),
		)
		return tok, claims, pErr
	}

	tok, claims, err := parseWithEntry(entry)
	if err != nil && strings.Contains(err.Error(), "unknown JWK kid") {
		if refreshed, rErr := getOrRefreshJWKS(ctx, cfg.OIDCIssuerURL, cfg.OIDCSkipTLSVerify, true); rErr == nil {
			entry = refreshed
			tok, claims, err = parseWithEntry(entry)
		}
	}
	if err != nil || tok == nil || !tok.Valid {
		return nil, fmt.Errorf("invalid OIDC token: %w", err)
	}

	audiences := append([]string{cfg.OIDCClientID}, cfg.OIDCExtraAudiences...)
	if !tokenMatchesAllowedAudience(claims, audiences) {
		return nil, fmt.Errorf("OIDC token audience does not match configured oidc_client_id %q", cfg.OIDCClientID)
	}

	sub, _ := claims.GetSubject()
	sub = strings.TrimSpace(sub)
	if sub == "" {
		return nil, fmt.Errorf("OIDC token missing sub claim")
	}

	merged := make(map[string]any, len(claims))
	for k, v := range claims {
		merged[k] = v
	}

	email, _ := merged["email"].(string)
	groups := ExtractOIDCGroups(merged)
	if strings.TrimSpace(optionalAccessToken) != "" && strings.TrimSpace(entry.disc.UserInfoEndpoint) != "" && (strings.TrimSpace(email) == "" || len(groups) == 0) {
		if uiClaims, uiErr := fetchOIDCUserInfo(ctx, entry.disc.UserInfoEndpoint, optionalAccessToken, cfg.OIDCSkipTLSVerify); uiErr == nil {
			if uiSub, _ := uiClaims["sub"].(string); strings.TrimSpace(uiSub) == sub {
				for k, v := range uiClaims {
					if _, exists := merged[k]; !exists || k == "groups" || k == "email" || k == "name" || k == "preferred_username" {
						merged[k] = v
					}
				}
			}
		}
	}

	email, _ = merged["email"].(string)
	name, _ := merged["name"].(string)
	username, _ := merged["preferred_username"].(string)

	return &OIDCVerifiedIdentity{
		Subject:   sub,
		Email:     strings.TrimSpace(email),
		Name:      strings.TrimSpace(name),
		Username:  strings.TrimSpace(username),
		Groups:    ExtractOIDCGroups(merged),
		RawClaims: merged,
	}, nil
}

func fetchOIDCUserInfo(ctx context.Context, userInfoURL string, accessToken string, skipTLSVerify bool) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(accessToken))
	resp, err := newOIDCHTTPClient(skipTLSVerify).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo HTTP %d", resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func generateUniqueOIDCUserID(pbApp core.App, name string, username string) string {
	source := strings.TrimSpace(name)
	if source == "" {
		source = strings.TrimSpace(username)
	}
	var base string
	if source != "" {
		words := strings.Fields(source)
		if len(words) >= 2 {
			first := string(unicode.ToUpper(rune(words[0][0])))
			last := string(unicode.ToUpper(rune(words[len(words)-1][0])))
			base = first + last
		} else if len(words) == 1 {
			word := words[0]
			if len(word) >= 2 {
				base = strings.ToUpper(word[:2])
			} else {
				base = strings.ToUpper(word) + strings.ToUpper(security.RandomString(2))
			}
		}
	}
	// Sanitize to alphanumeric for UserIDRegex ^[A-Za-z0-9]{1,20}$.
	var clean strings.Builder
	for _, r := range base {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			clean.WriteRune(unicode.ToUpper(r))
		}
	}
	base = clean.String()
	if base == "" {
		base = strings.ToUpper(security.RandomStringWithAlphabet(3, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
	}

	inUse := func(candidate string) bool {
		existing, err := pbApp.FindFirstRecordByData("users", "userID", candidate)
		if err != nil && err != sql.ErrNoRows {
			return true
		}
		if existing != nil {
			return true
		}
		return poolExists(candidate)
	}

	candidate := base
	for n := 2; ; n++ {
		if !inUse(candidate) && !slices.Contains(reservedInitialAdminUserIDs, candidate) {
			return candidate
		}
		candidate = base + strconv.Itoa(n)
	}
}

func generateUniqueProxmoxUsername(pbApp core.App, name string) string {
	raw := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(name)), " ", "-")
	var clean strings.Builder
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			clean.WriteRune(r)
		}
	}
	base := strings.Trim(clean.String(), "-_")
	if base == "" {
		base = "ludus-user"
	}
	candidate := base
	for n := 2; ; n++ {
		count, err := pbApp.CountRecords("users", dbx.HashExp{"proxmoxUsername": candidate})
		if err == nil && count == 0 && !userExistsOnHostSystem(candidate) {
			return candidate
		}
		candidate = fmt.Sprintf("%s-%d", base, n)
	}
}

func executeOAuth2UserProvisionDirect(pbApp core.App, req dto.ProvisionOAuth2UserRequest) (*core.Record, error) {
	userCollection, err := pbApp.FindCollectionByNameOrId("users")
	if err != nil {
		return nil, fmt.Errorf("finding users collection: %w", err)
	}
	userRecord := core.NewRecord(userCollection)
	user := &models.User{}
	user.SetProxyRecord(userRecord)
	user.SetName(req.Name)
	user.SetUserId(req.UserID)
	user.SetEmail(req.Email)
	user.SetPassword(req.Password)
	user.SetIsAdmin(req.IsAdmin)
	user.SetProxmoxUsername(req.ProxmoxUsername)
	user.SetProxmoxRealm(ConfiguredProxmoxRealm())
	encryptedPassword, err := EncryptStringForDatabase(req.Password)
	if err != nil {
		return nil, fmt.Errorf("encrypting password: %w", err)
	}
	user.SetProxmoxPassword(encryptedPassword)

	txErr := pbApp.RunInTransaction(func(txApp core.App) error {
		wasError := false
		defer func() {
			if wasError {
				removeUserFromHostSystem(user.ProxmoxUsername())
				removeUserFromProxmox(user.ProxmoxUsername(), user.ProxmoxRealm())
				removePool(user.UserId())
				defaultRangeRecord, findErr := txApp.FindFirstRecordByData("ranges", "rangeID", user.DefaultRangeId())
				if findErr == nil && defaultRangeRecord != nil {
					_ = txApp.Delete(defaultRangeRecord)
				}
				_ = txApp.Delete(user)
			}
		}()

		if _, pErr := provisionNewUser(txApp, user, req.Password); pErr != nil {
			wasError = true
			return pErr
		}
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}
	return pbApp.FindRecordById("users", user.Record.Id)
}

func requestAdminOAuth2Provision(pbApp core.App, req dto.ProvisionOAuth2UserRequest) (*core.Record, error) {
	if IsAdminProcess() {
		return executeOAuth2UserProvisionDirect(pbApp, req)
	}

	tokenPayload := fmt.Sprintf("%s|%s|%d", req.UserID, strconv.FormatBool(req.IsAdmin), time.Now().Unix())
	encryptedToken, err := EncryptStringForDatabase(tokenPayload)
	if err != nil {
		return nil, fmt.Errorf("encrypting internal token: %w", err)
	}
	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshalling provision request: %w", err)
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	adminScheme := "https"
	if !ServerConfiguration.IsTLSEnabled() {
		adminScheme = "http"
	}
	httpReq, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s://127.0.0.1:%d/api/v2/user/provision-oauth2", adminScheme, ServerConfiguration.AdminPort), bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("creating provision request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Internal-Token", encryptedToken)

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("calling admin API for provisioning: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading provision response: %w", err)
	}
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("admin API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	var provResp dto.ProvisionOAuth2UserResponse
	if err := json.Unmarshal(respBody, &provResp); err != nil {
		return nil, fmt.Errorf("parsing provision response: %w", err)
	}
	return pbApp.FindRecordById("users", provResp.RecordID)
}

func ensureOIDCExternalAuthLink(pbApp core.App, collectionID string, recordID string, subject string) {
	if strings.TrimSpace(subject) == "" {
		return
	}
	existing, err := pbApp.FindFirstExternalAuthByExpr(dbx.HashExp{
		"collectionRef": collectionID,
		"provider":      oidcProviderName,
		"providerId":    subject,
	})
	if err == nil && existing != nil {
		return
	}
	rel := core.NewExternalAuth(pbApp)
	rel.SetCollectionRef(collectionID)
	rel.SetRecordRef(recordID)
	rel.SetProvider(oidcProviderName)
	rel.SetProviderId(subject)
	_ = pbApp.Save(rel)
}

// AuthenticateAndSyncOIDCUser validates group membership, resolves or provisions the matching
// Ludus user record, synchronizes isAdmin from oidc_admin_groups when configured, and links _externalAuths.
func AuthenticateAndSyncOIDCUser(pbApp core.App, cfg *Configuration, identity *OIDCVerifiedIdentity) (*core.Record, error) {
	if identity == nil {
		return nil, fmt.Errorf("nil OIDC identity")
	}
	allowed, wantIsAdmin, _ := EvaluateOIDCGroupAccess(identity.RawClaims, cfg.OIDCAllowedGroups, cfg.OIDCAdminGroups)
	if !allowed {
		return nil, errOIDCGroupForbidden
	}

	usersCollection, err := pbApp.FindCollectionByNameOrId("users")
	if err != nil {
		return nil, fmt.Errorf("finding users collection: %w", err)
	}

	var record *core.Record
	var linked bool
	if identity.Subject != "" {
		if ext, extErr := pbApp.FindFirstExternalAuthByExpr(dbx.HashExp{
			"collectionRef": usersCollection.Id,
			"provider":      oidcProviderName,
			"providerId":    identity.Subject,
		}); extErr == nil && ext != nil {
			if rec, recErr := pbApp.FindRecordById("users", ext.RecordRef()); recErr == nil && rec != nil {
				record = rec
				linked = true
			}
		}
	}

	if record == nil && identity.Email != "" {
		if rec, recErr := pbApp.FindFirstRecordByData("users", "email", identity.Email); recErr == nil && rec != nil {
			record = rec
		}
	}

	if cfg.SSORequireExistingUser {
		if record == nil || identity.Email == "" || !strings.EqualFold(record.Email(), identity.Email) {
			return nil, errSSOExistingUserRequired
		}
	}

	if record == nil {
		if identity.Email == "" {
			return nil, fmt.Errorf("OIDC provider did not return an email address")
		}
		displayName := identity.Name
		if displayName == "" {
			displayName = identity.Username
		}
		if displayName == "" {
			displayName = strings.Split(identity.Email, "@")[0]
		}
		userID := generateUniqueOIDCUserID(pbApp, displayName, identity.Username)
		proxmoxUsername := generateUniqueProxmoxUsername(pbApp, displayName)
		req := dto.ProvisionOAuth2UserRequest{
			Name:            displayName,
			Email:           identity.Email,
			UserID:          userID,
			Password:        security.RandomString(20),
			ProxmoxUsername: proxmoxUsername,
			IsAdmin:         wantIsAdmin,
		}
		provisioned, provErr := requestAdminOAuth2Provision(pbApp, req)
		if provErr != nil {
			return nil, provErr
		}
		record = provisioned
	} else if len(cfg.OIDCAdminGroups) > 0 && record.GetBool("isAdmin") != wantIsAdmin {
		record.Set("isAdmin", wantIsAdmin)
		if saveErr := pbApp.Save(record); saveErr != nil {
			return nil, fmt.Errorf("synchronizing OIDC isAdmin status: %w", saveErr)
		}
	}

	if !linked && identity.Subject != "" {
		ensureOIDCExternalAuthLink(pbApp, usersCollection.Id, record.Id, identity.Subject)
	}

	return record, nil
}
