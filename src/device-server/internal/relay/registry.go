package relay

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type registryEntry struct {
	TenantID string   `json:"tenant_id"`
	Secret   string   `json:"secret"`
	URLs     []string `json:"urls"`
}
type registryFile struct {
	Bindings map[string]registryEntry `json:"bindings"`
}

// LoadIssuer reads one operator-selected configuration file, not a tenant-supplied
// filesystem reference. Secrets are exact printable text bytes, not Base64 decoded.
// An absent file setting means no approved relays; an invalid configured file fails.
func LoadIssuer(path string, ttl time.Duration, developmentLoopback bool) (*Issuer, error) {
	if path == "" {
		return New(nil, ttl, developmentLoopback)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrConfiguration
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrConfiguration
	}
	body, err := io.ReadAll(io.LimitReader(file, 128*1024+1))
	if err != nil || len(body) > 128*1024 {
		return nil, ErrConfiguration
	}
	var config registryFile
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&config); err != nil || len(config.Bindings) > 64 {
		return nil, ErrConfiguration
	}
	if err = decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, ErrConfiguration
	}
	bindings := make(map[string]SecretBinding, len(config.Bindings))
	for reference, entry := range config.Bindings {
		if entry.TenantID != "" && !uuidPattern.MatchString(entry.TenantID) {
			return nil, ErrConfiguration
		}
		bindings[reference] = SecretBinding{TenantID: strings.ToLower(entry.TenantID), Secret: []byte(entry.Secret), URLs: entry.URLs}
	}
	return New(bindings, ttl, developmentLoopback)
}

func LoadLimits(getenv func(string) string) (Limits, error) {
	limits := DefaultLimits()
	for _, item := range []struct {
		name   string
		target *int
	}{
		{"RELAY_TENANT_ISSUES_PER_MINUTE", &limits.TenantPerMinute},
		{"RELAY_DEVICE_ISSUES_PER_MINUTE", &limits.DevicePerMinute},
		{"RELAY_SESSION_ISSUES_PER_MINUTE", &limits.SessionPerMinute},
	} {
		if value := getenv(item.name); value != "" {
			number, err := strconv.Atoi(value)
			if err != nil {
				return Limits{}, ErrConfiguration
			}
			*item.target = number
		}
	}
	// Refresh margin is fixed in this slice. NewService validates against actual TTL.
	if err := limits.validate(time.Minute); err != nil {
		return Limits{}, err
	}
	return limits, nil
}

// LoadFromEnvironment has no secret values in errors. Development mode only
// permits explicitly approved literal loopback endpoints, not arbitrary URLs.
func LoadFromEnvironment(getenv func(string) string) (*Issuer, Limits, error) {
	ttl := 5 * time.Minute
	if value := getenv("RELAY_CREDENTIAL_TTL"); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return nil, Limits{}, ErrConfiguration
		}
		ttl = parsed
	}
	development := false
	if value := getenv("RELAY_DEVELOPMENT_LOOPBACK"); value != "" {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return nil, Limits{}, ErrConfiguration
		}
		development = parsed
	}
	issuer, err := LoadIssuer(getenv("RELAY_REGISTRY_FILE"), ttl, development)
	if err != nil {
		return nil, Limits{}, err
	}
	limits, err := LoadLimits(getenv)
	if err != nil {
		return nil, Limits{}, err
	}
	if err = limits.validate(ttl); err != nil {
		return nil, Limits{}, err
	}
	return issuer, limits, nil
}
