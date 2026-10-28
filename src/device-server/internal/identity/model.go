package identity

import (
	"encoding/json"
	"math"
	"regexp"
	"strings"
	"unicode/utf8"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type Registration struct {
	ApplicationID         string         `json:"application_id"`
	Platform              string         `json:"platform"`
	InstallationPublicKey string         `json:"installation_public_key"`
	RegistrationGrant     string         `json:"registration_grant"`
	SDKVersion            string         `json:"sdk_version,omitempty"`
	Metadata              map[string]any `json:"metadata,omitempty"`
}

func (r Registration) Validate() error {
	if !uuidPattern.MatchString(r.ApplicationID) {
		return Fail("INVALID_INPUT", 422)
	}
	switch r.Platform {
	case "windows", "macos", "linux", "android", "ios", "web":
	default:
		return Fail("INVALID_INPUT", 422)
	}
	if n := utf8.RuneCountInString(r.InstallationPublicKey); n < 1 || n > 4096 {
		return Fail("INVALID_INPUT", 422)
	}
	if n := len(r.RegistrationGrant); n < 1 || n > 512 {
		return Fail("GRANT_REQUIRED", 403)
	}
	if utf8.RuneCountInString(r.SDKVersion) > 64 || strings.ContainsRune(r.SDKVersion, 0) || len(r.Metadata) > 32 {
		return Fail("INVALID_INPUT", 422)
	}
	for key, value := range r.Metadata {
		if n := utf8.RuneCountInString(key); n < 1 || n > 64 || strings.ContainsRune(key, 0) {
			return Fail("INVALID_INPUT", 422)
		}
		switch v := value.(type) {
		case string:
			if utf8.RuneCountInString(v) > 1024 || strings.ContainsRune(v, 0) {
				return Fail("INVALID_INPUT", 422)
			}
		case nil, bool:
		case float64:
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return Fail("INVALID_INPUT", 422)
			}
		case json.Number:
			if _, err := v.Float64(); err != nil {
				return Fail("INVALID_INPUT", 422)
			}
		default:
			return Fail("INVALID_INPUT", 422)
		}
	}
	return nil
}

type Credential struct {
	DeviceID         string `json:"device_id"`
	DeviceCredential string `json:"device_credential"`
	ExpiresAt        string `json:"expires_at"`
}

type Device struct {
	ID            string          `json:"device_id"`
	TenantID      string          `json:"tenant_id"`
	ApplicationID string          `json:"application_id"`
	Platform      string          `json:"platform"`
	Metadata      json.RawMessage `json:"metadata"`
}

type Error struct {
	Code   string
	Status int
}

func (e *Error) Error() string           { return e.Code }
func Fail(code string, status int) error { return &Error{Code: code, Status: status} }
