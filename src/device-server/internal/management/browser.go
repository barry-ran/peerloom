package management

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
)

// BrowserIdentity is only produced by a configured server-side session authority.
// HTTP payloads cannot construct Principal, and begin revalidates the session inside
// the same tenant-serialized transaction as each management operation.
type BrowserIdentity struct{ TenantID, UserID, SessionID string }
type BrowserAuthority interface {
	AuthenticateBrowser(context.Context, string) (BrowserIdentity, error)
	RevalidateBrowser(context.Context, pgx.Tx, BrowserIdentity) (Scope, error)
}

// WithBrowserAuthority returns a copy; it does not change an already running service.
func (s *Service) WithBrowserAuthority(authority BrowserAuthority) (*Service, error) {
	if authority == nil {
		return nil, errors.New("browser session authority required")
	}
	result := *s
	result.browser = authority
	return &result, nil
}
func (s *Service) authenticateBrowser(ctx context.Context, token string) (Principal, error) {
	if s.browser == nil {
		return Principal{}, fail("ADMIN_AUTH_INVALID", 401)
	}
	identity, err := s.browser.AuthenticateBrowser(ctx, token)
	if err != nil {
		return Principal{}, err
	}
	if !uuidPattern.MatchString(identity.TenantID) || !uuidPattern.MatchString(identity.UserID) || !uuidPattern.MatchString(identity.SessionID) {
		return Principal{}, fail("ADMIN_AUTH_INVALID", 401)
	}
	return Principal{tenantID: identity.TenantID, credentialID: identity.UserID, browser: &identity}, nil
}
func (p Principal) actorType() string {
	if p.browser != nil {
		return "admin_user"
	}
	return "service_credential"
}
func (p Principal) replayTable() (string, string) {
	if p.browser != nil {
		return "admin_management_requests", "admin_user_id"
	}
	return "management_requests", "service_credential_id"
}
