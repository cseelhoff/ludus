package ludusapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"ludusapi/dto"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/hook"
)

func encodeRSAJWK(kid string, pub *rsa.PublicKey) map[string]any {
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(eBytes),
	}
}

func TestEvaluateOIDCGroupAccess(t *testing.T) {
	claims := map[string]any{
		"groups": []any{"/ludus-admins", "soc-analysts"},
		"realm_access": map[string]any{
			"roles": []any{"offline_access"},
		},
	}

	allowed, isAdmin, groups := EvaluateOIDCGroupAccess(claims, []string{"ludus-operators"}, []string{"ludus-admins"})
	if !allowed || !isAdmin {
		t.Fatalf("expected /ludus-admins to be allowed and promoted to admin; allowed=%v isAdmin=%v groups=%v", allowed, isAdmin, groups)
	}

	opClaims := map[string]any{"groups": []string{"ludus-operators"}}
	allowed, isAdmin, _ = EvaluateOIDCGroupAccess(opClaims, []string{"ludus-operators"}, []string{"ludus-admins"})
	if !allowed || isAdmin {
		t.Fatalf("expected ludus-operators to be allowed as non-admin; allowed=%v isAdmin=%v", allowed, isAdmin)
	}

	deniedClaims := map[string]any{"groups": []string{"random-guests"}}
	allowed, isAdmin, _ = EvaluateOIDCGroupAccess(deniedClaims, []string{"ludus-operators"}, []string{"ludus-admins"})
	if allowed || isAdmin {
		t.Fatalf("SECURITY VIOLATION: expected random-guests to be denied")
	}
}

func TestOIDCBootstrapExchangeRBACRotationAndLocalFallback(t *testing.T) {
	origCfg, origApp, origLogger := ServerConfiguration, app, logger
	t.Cleanup(func() {
		ResetOIDCCache()
		ResetProcessRole()
		ConfigMu.Lock()
		ServerConfiguration = origCfg
		ConfigMu.Unlock()
		app, logger = origApp, origLogger
	})
	ResetOIDCCache()
	SetAdminProcess(false)

	rsaKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey 1: %v", err)
	}
	rsaKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey 2: %v", err)
	}
	attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey attacker: %v", err)
	}

	var (
		jwksMu     sync.Mutex
		activeJWKs = []map[string]any{encodeRSAJWK("kid-1", &rsaKey1.PublicKey)}
	)

	var idpURL string
	idpSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/realms/sophon/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(OIDCDiscoveryDocument{
				Issuer:                idpURL + "/realms/sophon",
				AuthorizationEndpoint: idpURL + "/realms/sophon/protocol/openid-connect/auth",
				TokenEndpoint:         idpURL + "/realms/sophon/protocol/openid-connect/token",
				UserInfoEndpoint:      idpURL + "/realms/sophon/protocol/openid-connect/userinfo",
				JWKSURI:               idpURL + "/realms/sophon/protocol/openid-connect/certs",
			})
		case "/realms/sophon/protocol/openid-connect/certs":
			jwksMu.Lock()
			keys := append([]map[string]any(nil), activeJWKs...)
			jwksMu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
		default:
			http.NotFound(w, r)
		}
	}))
	defer idpSrv.Close()
	idpURL = idpSrv.URL

	secretFile := filepath.Join(t.TempDir(), "oidc_secret")
	if err := os.WriteFile(secretFile, []byte("super-secret-keycloak-client\n"), 0400); err != nil {
		t.Fatalf("write secret file: %v", err)
	}

	pb := core.NewBaseApp(core.BaseAppConfig{DataDir: t.TempDir()})
	if err := pb.Bootstrap(); err != nil {
		t.Fatalf("pb.Bootstrap: %v", err)
	}
	t.Cleanup(func() { pb.ResetBootstrapState() })
	if err := pb.RunSystemMigrations(); err != nil {
		t.Fatalf("pb.RunSystemMigrations: %v", err)
	}
	pb.Settings().Logs.MaxDays = 0
	app = pb
	logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	usersCol, err := pb.FindCollectionByNameOrId("users")
	if err != nil {
		usersCol = core.NewAuthCollection("users")
	}
	usersCol.Fields.Add(
		&core.TextField{Name: "name"},
		&core.TextField{Name: "userID"},
		&core.TextField{Name: "proxmoxUsername"},
		&core.TextField{Name: "defaultRangeID"},
		&core.BoolField{Name: "isAdmin"},
	)
	if err := pb.Save(usersCol); err != nil {
		t.Fatalf("saving users collection: %v", err)
	}

	// Create a local break-glass user to test native PocketBase password login fallback!
	localUser := core.NewRecord(usersCol)
	localUser.SetEmail("breakglass@ludus.local")
	localUser.SetPassword("local-fallback-pass-123")
	localUser.SetVerified(true)
	localUser.Set("name", "Break Glass Admin")
	localUser.Set("userID", "BG")
	localUser.Set("proxmoxUsername", "break-glass")
	localUser.Set("defaultRangeID", "BG")
	localUser.Set("isAdmin", true)
	if err := pb.Save(localUser); err != nil {
		t.Fatalf("saving local user: %v", err)
	}

	// Mock internal admin provisioning listener (127.0.0.1:<port>/api/v2/user/provision-oauth2)
	adminSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req dto.ProvisionOAuth2UserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		col, _ := pb.FindCollectionByNameOrId("users")
		rec := core.NewRecord(col)
		rec.SetEmail(req.Email)
		rec.SetPassword(req.Password)
		rec.SetVerified(true)
		rec.Set("name", req.Name)
		rec.Set("userID", req.UserID)
		rec.Set("proxmoxUsername", req.ProxmoxUsername)
		rec.Set("defaultRangeID", req.UserID)
		rec.Set("isAdmin", req.IsAdmin)
		if err := pb.Save(rec); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(dto.ProvisionOAuth2UserResponse{RecordID: rec.Id})
	}))
	defer adminSrv.Close()
	_, adminPortStr, _ := net.SplitHostPort(adminSrv.Listener.Addr().String())
	adminPort, _ := strconv.Atoi(adminPortStr)

	tlsFalse := false
	cfg := Configuration{
		ContainerMode:          true,
		TLSEnabled:             &tlsFalse,
		AdminPort:              adminPort,
		DatabaseEncryptionKey:  strings.Repeat("k", 32),
		SSORequireExistingUser: false,
		OIDCEnabled:            true,
		OIDCDisplayName:        "Sophon SSO",
		OIDCIssuerURL:          idpURL + "/realms/sophon",
		OIDCClientID:           "ludus",
		OIDCClientSecretFile:   secretFile,
		OIDCSkipTLSVerify:      true,
		OIDCAllowedGroups:      []string{"ludus-operators", "ludus-admins"},
		OIDCAdminGroups:        []string{"ludus-admins"},
	}
	cfg.ApplyRemoteProxmoxDefaults()
	ConfigMu.Lock()
	ServerConfiguration = cfg
	ConfigMu.Unlock()

	// 1. Test ReconcileDeclarativeOIDCProvider idempotency.
	if err := ReconcileDeclarativeOIDCProvider(context.Background(), pb, &cfg); err != nil {
		t.Fatalf("ReconcileDeclarativeOIDCProvider #1: %v", err)
	}
	if err := ReconcileDeclarativeOIDCProvider(context.Background(), pb, &cfg); err != nil {
		t.Fatalf("ReconcileDeclarativeOIDCProvider #2: %v", err)
	}
	reloadedCol, err := pb.FindCollectionByNameOrId("users")
	if err != nil {
		t.Fatalf("reloading users collection: %v", err)
	}
	if !reloadedCol.OAuth2.Enabled || len(reloadedCol.OAuth2.Providers) != 1 || reloadedCol.OAuth2.Providers[0].Name != "oidc" {
		t.Fatalf("unexpected OAuth2 providers after idempotent reconcile: %+v", reloadedCol.OAuth2)
	}

	// Build real PocketBase router with our auth routes and requireAuth middleware!
	pbRouter, err := apis.NewRouter(pb)
	if err != nil {
		t.Fatalf("apis.NewRouter: %v", err)
	}
	pbRouter.Bind(&hook.Handler[*core.RequestEvent]{
		Id:       "requireAuth",
		Func:     requireAuth,
		Priority: 1004,
	})
	pbRouter.GET(APIBasePath+"/auth/providers", GetAuthProviders)
	pbRouter.POST(APIBasePath+"/auth/oidc-exchange", ExchangeOIDCToken)
	pbRouter.POST(APIBasePath+"/auth/login", LocalPasswordLogin)
	pbRouter.POST(APIBasePath+"/auth/impersonate", AdminImpersonateToken)
	pbRouter.GET(APIBasePath+"/auth/me", GetAuthenticatedUserMe)
	mux, err := pbRouter.BuildMux()
	if err != nil {
		t.Fatalf("pbRouter.BuildMux: %v", err)
	}
	apiSrv := httptest.NewServer(mux)
	defer apiSrv.Close()

	mintToken := func(priv *rsa.PrivateKey, kid string, sub string, email string, name string, groups []string) string {
		now := time.Now()
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss":                idpURL + "/realms/sophon",
			"sub":                sub,
			"aud":                "ludus",
			"email":              email,
			"name":               name,
			"preferred_username": strings.Split(email, "@")[0],
			"groups":             groups,
			"iat":                now.Unix(),
			"exp":                now.Add(5 * time.Minute).Unix(),
		})
		tok.Header["kid"] = kid
		signed, sErr := tok.SignedString(priv)
		if sErr != nil {
			t.Fatalf("SignedString: %v", sErr)
		}
		return signed
	}

	// 2. Public GET /api/v2/auth/providers works without auth and leaks zero secrets.
	provResp, err := http.Get(apiSrv.URL + "/api/v2/auth/providers")
	if err != nil || provResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /auth/providers failed: err=%v status=%v", err, provResp)
	}
	provBody, _ := io.ReadAll(provResp.Body)
	_ = provResp.Body.Close()
	if strings.Contains(string(provBody), "super-secret") || !strings.Contains(string(provBody), `"oidcEnabled":true`) {
		t.Fatalf("unexpected /auth/providers payload: %s", string(provBody))
	}

	// 3. Forged token signed with attacker key must return 401!
	forgedJWT := mintToken(attackerKey, "kid-1", "sub-1", "caleb@sophon.test", "Caleb Seelhoff", []string{"ludus-admins"})
	resForged, _ := http.Post(apiSrv.URL+"/api/v2/auth/oidc-exchange", "application/json",
		strings.NewReader(`{"idToken":"`+forgedJWT+`"}`))
	_ = resForged.Body.Close()
	if resForged.StatusCode != http.StatusUnauthorized {
		t.Fatalf("SECURITY VIOLATION: forged JWT returned HTTP %d, want 401", resForged.StatusCode)
	}

	// 4. Disallowed group must return 403!
	guestJWT := mintToken(rsaKey1, "kid-1", "sub-guest", "guest@sophon.test", "Guest User", []string{"untrusted-group"})
	resGuest, _ := http.Post(apiSrv.URL+"/api/v2/auth/oidc-exchange", "application/json",
		strings.NewReader(`{"idToken":"`+guestJWT+`"}`))
	_ = resGuest.Body.Close()
	if resGuest.StatusCode != http.StatusForbidden {
		t.Fatalf("SECURITY VIOLATION: disallowed group returned HTTP %d, want 403", resGuest.StatusCode)
	}

	// 5. Valid ludus-admins login auto-provisions user with isAdmin=true and returns working PocketBase JWT!
	adminOIDCJWT := mintToken(rsaKey1, "kid-1", "sub-caleb", "caleb@sophon.test", "Caleb Seelhoff", []string{"/ludus-admins"})
	resAdmin, err := http.Post(apiSrv.URL+"/api/v2/auth/oidc-exchange", "application/json",
		strings.NewReader(`{"idToken":"`+adminOIDCJWT+`"}`))
	if err != nil || resAdmin.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resAdmin.Body)
		t.Fatalf("valid OIDC exchange failed: status=%d body=%s err=%v", resAdmin.StatusCode, string(body), err)
	}
	var exch OIDCExchangeResponse
	_ = json.NewDecoder(resAdmin.Body).Decode(&exch)
	_ = resAdmin.Body.Close()
	if exch.Token == "" || !exch.User.IsAdmin || exch.User.UserID != "CS" {
		t.Fatalf("unexpected OIDC exchange response: %+v", exch)
	}

	// Verify GET /api/v2/auth/me with issued Bearer JWT!
	meReq, _ := http.NewRequest(http.MethodGet, apiSrv.URL+"/api/v2/auth/me", nil)
	meReq.Header.Set("Authorization", "Bearer "+exch.Token)
	meResp, err := http.DefaultClient.Do(meReq)
	if err != nil || meResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /auth/me with OIDC-exchanged token failed: %v %v", err, meResp)
	}
	var meProfile AuthUserProfile
	_ = json.NewDecoder(meResp.Body).Decode(&meProfile)
	_ = meResp.Body.Close()
	if meProfile.UserID != "CS" || !meProfile.IsAdmin {
		t.Fatalf("unexpected /auth/me profile: %+v", meProfile)
	}

	// 6. Test JWKS key rotation (kid-2) + dynamic isAdmin demotion when removed from ludus-admins!
	// Advance lastRefresh window bypass by resetting cache age slightly or waiting >5s? Let's test kid miss refresh after backdating lastRefresh!
	globalJWKSMu.Lock()
	for _, entry := range globalJWKSCache {
		entry.lastRefresh = time.Now().Add(-10 * time.Second)
	}
	globalJWKSMu.Unlock()
	jwksMu.Lock()
	activeJWKs = []map[string]any{encodeRSAJWK("kid-2", &rsaKey2.PublicKey)}
	jwksMu.Unlock()

	demotedJWT := mintToken(rsaKey2, "kid-2", "sub-caleb", "caleb@sophon.test", "Caleb Seelhoff", []string{"ludus-operators"})
	resDemoted, err := http.Post(apiSrv.URL+"/api/v2/auth/oidc-exchange", "application/json",
		strings.NewReader(`{"idToken":"`+demotedJWT+`"}`))
	if err != nil || resDemoted.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resDemoted.Body)
		t.Fatalf("rotated JWKS OIDC exchange failed: status=%d body=%s err=%v", resDemoted.StatusCode, string(body), err)
	}
	var exchDemoted OIDCExchangeResponse
	_ = json.NewDecoder(resDemoted.Body).Decode(&exchDemoted)
	_ = resDemoted.Body.Close()
	if exchDemoted.User.UserID != "CS" || exchDemoted.User.IsAdmin {
		t.Fatalf("expected CS to retain account and dynamically sync isAdmin=false, got %+v", exchDemoted.User)
	}

	// 7. Test native PocketBase local password fallback (POST /api/collections/users/auth-with-password -> GET /api/v2/auth/me)!
	localLoginBody, _ := json.Marshal(map[string]string{
		"identity": "breakglass@ludus.local",
		"password": "local-fallback-pass-123",
	})
	resLocal, err := http.Post(apiSrv.URL+"/api/collections/users/auth-with-password", "application/json", bytes.NewReader(localLoginBody))
	if err != nil || resLocal.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resLocal.Body)
		t.Fatalf("local password auth fallback failed: status=%d body=%s err=%v", resLocal.StatusCode, string(body), err)
	}
	var pbAuth struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(resLocal.Body).Decode(&pbAuth)
	_ = resLocal.Body.Close()
	if pbAuth.Token == "" {
		t.Fatalf("expected non-empty token from local auth-with-password")
	}

	localMeReq, _ := http.NewRequest(http.MethodGet, apiSrv.URL+"/api/v2/auth/me", nil)
	localMeReq.Header.Set("Authorization", "Bearer "+pbAuth.Token)
	localMeResp, err := http.DefaultClient.Do(localMeReq)
	if err != nil || localMeResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /auth/me with local fallback token failed: %v %v", err, localMeResp)
	}
	var localProfile AuthUserProfile
	_ = json.NewDecoder(localMeResp.Body).Decode(&localProfile)
	_ = localMeResp.Body.Close()
	if localProfile.UserID != "BG" || !localProfile.IsAdmin {
		t.Fatalf("unexpected local fallback /auth/me profile: %+v", localProfile)
	}

	// 8. Test unified SSH-free local login endpoint (POST /api/v2/auth/login) by userID, wrong password, and ROOT block!
	resUserIDLogin, err := http.Post(apiSrv.URL+"/api/v2/auth/login", "application/json",
		strings.NewReader(`{"identity":"BG","password":"local-fallback-pass-123"}`))
	if err != nil || resUserIDLogin.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resUserIDLogin.Body)
		t.Fatalf("POST /auth/login by userID failed: status=%d body=%s err=%v", resUserIDLogin.StatusCode, string(body), err)
	}
	var loginExch OIDCExchangeResponse
	_ = json.NewDecoder(resUserIDLogin.Body).Decode(&loginExch)
	_ = resUserIDLogin.Body.Close()
	if loginExch.Token == "" || loginExch.User.UserID != "BG" || !loginExch.User.IsAdmin {
		t.Fatalf("unexpected /auth/login response: %+v", loginExch)
	}

	resBadPass, _ := http.Post(apiSrv.URL+"/api/v2/auth/login", "application/json",
		strings.NewReader(`{"identity":"BG","password":"wrong-password"}`))
	_ = resBadPass.Body.Close()
	if resBadPass.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on wrong password, got %d", resBadPass.StatusCode)
	}

	resRootLogin, _ := http.Post(apiSrv.URL+"/api/v2/auth/login", "application/json",
		strings.NewReader(`{"identity":"ROOT","password":"any"}`))
	_ = resRootLogin.Body.Close()
	if resRootLogin.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 when attempting interactive ROOT login, got %d", resRootLogin.StatusCode)
	}

	// 9. Test SSH-free admin impersonation token minting (admin succeeds, non-admin gets 403)!
	nonAdminImpReq, _ := http.NewRequest(http.MethodPost, apiSrv.URL+"/api/v2/auth/impersonate", strings.NewReader(`{"userID":"BG"}`))
	nonAdminImpReq.Header.Set("Authorization", "Bearer "+exchDemoted.Token)
	nonAdminImpReq.Header.Set("Content-Type", "application/json")
	nonAdminImpResp, _ := http.DefaultClient.Do(nonAdminImpReq)
	_ = nonAdminImpResp.Body.Close()
	if nonAdminImpResp.StatusCode != http.StatusForbidden {
		t.Fatalf("SECURITY VIOLATION: non-admin /auth/impersonate returned %d, want 403", nonAdminImpResp.StatusCode)
	}

	adminImpReq, _ := http.NewRequest(http.MethodPost, apiSrv.URL+"/api/v2/auth/impersonate", strings.NewReader(`{"userID":"CS"}`))
	adminImpReq.Header.Set("Authorization", "Bearer "+loginExch.Token)
	adminImpReq.Header.Set("Content-Type", "application/json")
	adminImpResp, err := http.DefaultClient.Do(adminImpReq)
	if err != nil || adminImpResp.StatusCode != http.StatusOK {
		t.Fatalf("admin /auth/impersonate failed: err=%v resp=%v", err, adminImpResp)
	}
	var impExch OIDCExchangeResponse
	_ = json.NewDecoder(adminImpResp.Body).Decode(&impExch)
	_ = adminImpResp.Body.Close()
	if impExch.Token == "" || impExch.User.UserID != "CS" {
		t.Fatalf("unexpected /auth/impersonate response: %+v", impExch)
	}
}
