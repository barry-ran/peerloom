// Package management implements tenant-scoped service-key administration.
// It deliberately does not implement interactive login or an OIDC decision.
package management

import (
	"errors"
	"regexp"
	"time"
)

type Scope string

const (
	ScopeRead  Scope = "read"
	ScopeAdmin Scope = "admin"
)

// Principal has no public fields: HTTP payloads cannot construct authority.
// Mutation transactions still revalidate current database permissions.
type Principal struct {
	tenantID, credentialID string
	scope                  Scope
}

func (p Principal) TenantID() string     { return p.tenantID }
func (p Principal) CredentialID() string { return p.credentialID }
func (p Principal) Scope() Scope         { return p.scope }

type Settings struct{ ResponseTTL, ReceiptTTL time.Duration }

func DefaultSettings() Settings {
	return Settings{ResponseTTL: 10 * time.Minute, ReceiptTTL: 24 * time.Hour}
}
func (s Settings) validate() error {
	if s.ResponseTTL < time.Second || s.ResponseTTL > time.Hour || s.ReceiptTTL < s.ResponseTTL || s.ReceiptTTL > 7*24*time.Hour {
		return errors.New("management replay durations outside safe bounds")
	}
	return nil
}

type Error struct {
	Code   string
	Status int
}

func (e *Error) Error() string           { return e.Code }
func fail(code string, status int) error { return &Error{Code: code, Status: status} }

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type KeyResult struct {
	TenantID          string    `json:"tenant_id"`
	CredentialID      string    `json:"credential_id"`
	ServiceCredential string    `json:"service_credential"`
	Scope             Scope     `json:"scope"`
	ExpiresAt         time.Time `json:"expires_at"`
}

type ApplicationInput struct {
	Name                  string `json:"name"`
	RegistrationMode      string `json:"registration_mode,omitempty"`
	RequireTargetApproval bool   `json:"require_target_approval"`
	MaxConnections        *int   `json:"max_connections,omitempty"`
}

type Application struct {
	ID                    string    `json:"id"`
	TenantID              string    `json:"tenant_id"`
	Name                  string    `json:"name"`
	RegistrationMode      string    `json:"registration_mode"`
	RequireTargetApproval bool      `json:"require_target_approval"`
	MaxConnections        int       `json:"max_connections"`
	Enabled               bool      `json:"enabled"`
	CreatedAt             time.Time `json:"created_at"`
}

type RegistrationGrantInput struct {
	ApplicationID    string `json:"application_id"`
	ExpiresInSeconds int    `json:"expires_in_seconds,omitempty"`
}

type RegistrationGrant struct {
	ID        string    `json:"id"`
	Grant     string    `json:"grant"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Page struct {
	Limit  int
	Cursor string
}
type ApplicationPage struct {
	Items      []Application `json:"items"`
	NextCursor string        `json:"next_cursor,omitempty"`
}
