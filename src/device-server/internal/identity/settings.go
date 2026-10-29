package identity

import (
	"errors"
	"strconv"
	"time"
)

type Settings struct {
	DirectGlobalPerMinute int
	DirectIPPerMinute     int
	DirectAppPerMinute    int
	DirectAppPerDay       int
	DirectAppDevices      int
	CredentialTTL         time.Duration
	ReplayTTL             time.Duration
	RotationOverlap       time.Duration
}

func DefaultSettings() Settings {
	return Settings{CredentialTTL: 24 * time.Hour, ReplayTTL: 10 * time.Minute, RotationOverlap: 30 * time.Second}
}

func LoadSettings(getenv func(string) string) (Settings, error) {
	settings := DefaultSettings()
	for _, item := range []struct {
		name   string
		target *time.Duration
	}{
		{"CREDENTIAL_TTL", &settings.CredentialTTL},
		{"REPLAY_TTL", &settings.ReplayTTL},
		{"ROTATION_OVERLAP", &settings.RotationOverlap},
	} {
		if value := getenv(item.name); value != "" {
			parsed, err := time.ParseDuration(value)
			if err != nil {
				return Settings{}, errors.New("invalid identity duration configuration")
			}
			*item.target = parsed
		}
	}
	for _, item := range []struct {
		name   string
		target *int
	}{
		{"DIRECT_GLOBAL_PER_MINUTE", &settings.DirectGlobalPerMinute},
		{"DIRECT_IP_PER_MINUTE", &settings.DirectIPPerMinute},
		{"DIRECT_APP_PER_MINUTE", &settings.DirectAppPerMinute},
		{"DIRECT_APP_PER_DAY", &settings.DirectAppPerDay},
		{"DIRECT_APP_DEVICES", &settings.DirectAppDevices},
	} {
		if value := getenv(item.name); value != "" {
			parsed, err := strconv.Atoi(value)
			if err != nil {
				return Settings{}, errors.New("invalid direct registration quota")
			}
			*item.target = parsed
		}
	}
	if err := settings.Validate(); err != nil {
		return Settings{}, err
	}
	return settings, nil
}

func (s Settings) Validate() error {
	for _, limit := range []int{s.DirectGlobalPerMinute, s.DirectIPPerMinute, s.DirectAppPerMinute, s.DirectAppPerDay, s.DirectAppDevices} {
		if limit < 0 || limit > 2147483647 {
			return errors.New("direct registration quota outside SQL integer representation")
		}
	}
	if s.CredentialTTL < time.Minute || s.CredentialTTL > 30*24*time.Hour || s.ReplayTTL < time.Second || s.ReplayTTL > time.Hour || s.RotationOverlap < time.Second || s.RotationOverlap > 5*time.Minute || s.RotationOverlap > s.CredentialTTL || s.ReplayTTL > s.CredentialTTL {
		return errors.New("identity durations outside safe bounds")
	}
	return nil
}
