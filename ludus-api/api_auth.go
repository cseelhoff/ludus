package ludusapi

import (
	"errors"
	"fmt"
	"ludusapi/models"
	"net/http"
	"strings"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

// AuthProvidersResponse reports the active UI authentication methods (zero secrets).
type AuthProvidersResponse struct {
	LocalAuthEnabled bool   `json:"localAuthEnabled"`
	OIDCEnabled      bool   `json:"oidcEnabled"`
	OIDCDisplayName  string `json:"oidcDisplayName,omitempty"`
	OIDCIssuerURL    string `json:"oidcIssuerURL,omitempty"`
	OIDCClientID     string `json:"oidcClientID,omitempty"`
}

// OIDCExchangeRequest carries an OIDC ID token (and optional access token) from LUX.
type OIDCExchangeRequest struct {
	IDToken     string `json:"idToken"`
	AccessToken string `json:"accessToken,omitempty"`
	Token       string `json:"token,omitempty"`
}

// AuthUserProfile describes the authenticated Ludus user for LUX sessions.
type AuthUserProfile struct {
	ID              string   `json:"id"`
	UserID          string   `json:"userID"`
	Name            string   `json:"name"`
	Email           string   `json:"email"`
	IsAdmin         bool     `json:"isAdmin"`
	ProxmoxUsername string   `json:"proxmoxUsername,omitempty"`
	DefaultRangeID  string   `json:"defaultRangeID,omitempty"`
	Groups          []string `json:"groups,omitempty"`
}

// OIDCExchangeResponse returns a PocketBase JWT and normalized Ludus user profile.
type OIDCExchangeResponse struct {
	Token string          `json:"token"`
	User  AuthUserProfile `json:"user"`
}

func buildAuthUserProfile(record *core.Record, groups []string) AuthUserProfile {
	u := &models.User{}
	u.SetProxyRecord(record)
	return AuthUserProfile{
		ID:              record.Id,
		UserID:          u.UserId(),
		Name:            u.Name(),
		Email:           record.Email(),
		IsAdmin:         u.IsAdmin(),
		ProxmoxUsername: u.ProxmoxUsername(),
		DefaultRangeID:  u.DefaultRangeId(),
		Groups:          groups,
	}
}

// GetAuthProviders returns public authentication discovery metadata for LUX.
func GetAuthProviders(e *core.RequestEvent) error {
	ConfigMu.RLock()
	cfg := ServerConfiguration
	ConfigMu.RUnlock()

	resp := AuthProvidersResponse{
		LocalAuthEnabled: true,
		OIDCEnabled:      cfg.OIDCEnabled,
	}
	if cfg.OIDCEnabled {
		resp.OIDCDisplayName = cfg.OIDCDisplayName
		resp.OIDCIssuerURL = cfg.OIDCIssuerURL
		resp.OIDCClientID = cfg.OIDCClientID
	}
	return e.JSON(http.StatusOK, resp)
}

// ExchangeOIDCToken validates an OIDC ID/Access token against the configured OIDC issuer JWKS,
// enforces oidc_allowed_groups / oidc_admin_groups, provisions or loads the Ludus user, and
// issues a PocketBase authentication JWT for pure HTTPS/HTTP REST communication.
func ExchangeOIDCToken(e *core.RequestEvent) error {
	ConfigMu.RLock()
	cfg := ServerConfiguration
	ConfigMu.RUnlock()

	if !cfg.OIDCEnabled {
		return JSONError(e, http.StatusNotFound, "OIDC authentication is not enabled on this Ludus server")
	}

	var req OIDCExchangeRequest
	if err := e.BindBody(&req); err != nil {
		return JSONError(e, http.StatusBadRequest, fmt.Sprintf("Invalid OIDC exchange payload: %v", err))
	}

	primaryToken := strings.TrimSpace(req.IDToken)
	if primaryToken == "" {
		primaryToken = strings.TrimSpace(req.Token)
	}
	if primaryToken == "" {
		primaryToken = strings.TrimSpace(req.AccessToken)
	}
	if primaryToken == "" {
		return JSONError(e, http.StatusBadRequest, "idToken (or token / accessToken) is required")
	}

	identity, err := VerifyOIDCToken(e.Request.Context(), &cfg, primaryToken, req.AccessToken)
	if err != nil {
		return JSONError(e, http.StatusUnauthorized, fmt.Sprintf("OIDC token verification failed: %v", err))
	}

	record, err := AuthenticateAndSyncOIDCUser(e.App, &cfg, identity)
	if err != nil {
		if errors.Is(err, errOIDCGroupForbidden) || errors.Is(err, errSSOExistingUserRequired) {
			return JSONError(e, http.StatusForbidden, err.Error())
		}
		return JSONError(e, http.StatusInternalServerError, fmt.Sprintf("OIDC user provisioning failed: %v", err))
	}

	pbToken, err := record.NewAuthToken()
	if err != nil {
		return JSONError(e, http.StatusInternalServerError, fmt.Sprintf("Failed to issue Ludus session token: %v", err))
	}

	return e.JSON(http.StatusOK, OIDCExchangeResponse{
		Token: pbToken,
		User:  buildAuthUserProfile(record, identity.Groups),
	})
}

// LocalLoginRequest carries local fallback credentials (email, userID, or proxmoxUsername + password).
type LocalLoginRequest struct {
	Identity string `json:"identity"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// LocalPasswordLogin authenticates a non-ROOT Ludus user by email, userID, or proxmoxUsername
// and issues a PocketBase JWT + normalized AuthUserProfile without SSH or ~/.bashrc access.
func LocalPasswordLogin(e *core.RequestEvent) error {
	var req LocalLoginRequest
	if err := e.BindBody(&req); err != nil {
		return JSONError(e, http.StatusBadRequest, fmt.Sprintf("Invalid login payload: %v", err))
	}

	identity := strings.TrimSpace(req.Identity)
	if identity == "" {
		identity = strings.TrimSpace(req.Username)
	}
	if identity == "" || req.Password == "" {
		return JSONError(e, http.StatusBadRequest, "Username/email and password are required")
	}

	record := findLocalAuthUserRecord(e.App, identity)
	if record == nil || strings.EqualFold(record.GetString("userID"), "ROOT") || !record.ValidatePassword(req.Password) {
		return JSONError(e, http.StatusUnauthorized, "Invalid username or password")
	}

	pbToken, err := record.NewAuthToken()
	if err != nil {
		return JSONError(e, http.StatusInternalServerError, fmt.Sprintf("Failed to issue Ludus session token: %v", err))
	}

	return e.JSON(http.StatusOK, OIDCExchangeResponse{
		Token: pbToken,
		User:  buildAuthUserProfile(record, nil),
	})
}

func findLocalAuthUserRecord(pbApp core.App, identity string) *core.Record {
	lower := strings.ToLower(strings.TrimSpace(identity))
	if lower == "" {
		return nil
	}
	if rec, err := pbApp.FindAuthRecordByEmail("users", lower); err == nil && rec != nil {
		return rec
	}
	var records []*core.Record
	err := pbApp.RecordQuery("users").
		AndWhere(dbx.NewExp("LOWER(userID) = {:id} OR LOWER(proxmoxUsername) = {:id}", dbx.Params{"id": lower})).
		Limit(2).
		All(&records)
	if err == nil && len(records) == 1 {
		return records[0]
	}
	return nil
}

// ImpersonateRequest requests a scoped PocketBase JWT for a non-ROOT target user (admin-only).
type ImpersonateRequest struct {
	UserID string `json:"userID"`
}

// AdminImpersonateToken issues a PocketBase session JWT for a target Ludus user when called by an admin,
// enabling SSH-free admin impersonation in LUX without scraping ~/.bashrc.
func AdminImpersonateToken(e *core.RequestEvent) error {
	if e.Auth == nil {
		return JSONError(e, http.StatusUnauthorized, "Authentication required")
	}
	caller := &models.User{}
	caller.SetProxyRecord(e.Auth)
	if !caller.IsAdmin() {
		return JSONError(e, http.StatusForbidden, "Admin privileges required")
	}

	var req ImpersonateRequest
	if err := e.BindBody(&req); err != nil {
		return JSONError(e, http.StatusBadRequest, fmt.Sprintf("Invalid impersonation payload: %v", err))
	}
	targetID := strings.TrimSpace(req.UserID)
	if targetID == "" {
		return JSONError(e, http.StatusBadRequest, "userID is required")
	}

	target := findLocalAuthUserRecord(e.App, targetID)
	if target == nil || strings.EqualFold(target.GetString("userID"), "ROOT") {
		return JSONError(e, http.StatusNotFound, fmt.Sprintf("User %s not found", targetID))
	}

	pbToken, err := target.NewAuthToken()
	if err != nil {
		return JSONError(e, http.StatusInternalServerError, fmt.Sprintf("Failed to issue impersonation token: %v", err))
	}

	return e.JSON(http.StatusOK, OIDCExchangeResponse{
		Token: pbToken,
		User:  buildAuthUserProfile(target, nil),
	})
}

// GetAuthenticatedUserMe returns the normalized Ludus user profile for the caller's Bearer JWT or X-API-KEY.
func GetAuthenticatedUserMe(e *core.RequestEvent) error {
	if e.Auth == nil {
		return JSONError(e, http.StatusUnauthorized, "Authentication required")
	}
	return e.JSON(http.StatusOK, buildAuthUserProfile(e.Auth, nil))
}
