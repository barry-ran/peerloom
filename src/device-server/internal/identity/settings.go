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
	ReplayTTL             time.Duration
}

func DefaultSettings() Settings {
	return Settings{ReplayTTL: 10 * time.Minute}
}

func LoadSettings(getenv func(string) string) (Settings, error) {
	if getenv("CREDENTIAL_TTL") != "" || getenv("ROTATION_OVERLAP") != "" {
		return Settings{}, errors.New("obsolete credential lifetime settings are not supported")
	}
	settings := DefaultSettings()
	for _, item := range []struct {
		name   string
		target *time.Duration
	}{
		{"REPLAY_TTL", &settings.ReplayTTL},
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
	if s.ReplayTTL < time.Second || s.ReplayTTL > time.Hour {
		return errors.New("identity durations outside safe bounds")
	}
	return nil
}
