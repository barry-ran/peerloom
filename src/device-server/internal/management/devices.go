package management

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

type Presence interface {
	Online(context.Context, string, string) (bool, error)
}

type Device struct {
	ID             string         `json:"id"`
	TenantID       string         `json:"tenant_id"`
	ApplicationID  string         `json:"application_id"`
	Platform       string         `json:"platform"`
	DisplayName    string         `json:"display_name"`
	Metadata       map[string]any `json:"metadata"`
	Tags           map[string]any `json:"tags"`
	Connectable    bool           `json:"connectable"`
	MaxConnections *int           `json:"max_connections"`
	Status         string         `json:"status"`
	Online         *bool          `json:"online"`
	CreatedAt      time.Time      `json:"created_at"`
}

// OptionalInt preserves omitted vs explicit null (inherit application limit).
type OptionalInt struct {
	Set   bool
	Value *int
}

func (value *OptionalInt) UnmarshalJSON(data []byte) error {
	value.Set = true
	return json.Unmarshal(data, &value.Value)
}

type DeviceUpdate struct {
	DisplayName    *string         `json:"display_name"`
	Metadata       *map[string]any `json:"metadata"`
	Tags           *map[string]any `json:"tags"`
	Connectable    *bool           `json:"connectable"`
	MaxConnections OptionalInt     `json:"max_connections"`
}

const deviceColumns = "id::text,tenant_id::text,application_id::text,platform,COALESCE(display_name,''),metadata,tags,connectable,max_connections,status,created_at"

func scanDevice(row scanner) (Device, error) {
	var value Device
	err := row.Scan(&value.ID, &value.TenantID, &value.ApplicationID, &value.Platform, &value.DisplayName, &value.Metadata, &value.Tags, &value.Connectable, &value.MaxConnections, &value.Status, &value.CreatedAt)
	return value, err
}

func validProperties(value map[string]any) bool {
	if len(value) > 32 {
		return false
	}
	for key, item := range value {
		if !validText(key, 64) {
			return false
		}
		switch typed := item.(type) {
		case nil, bool:
		case string:
			if utf8.RuneCountInString(typed) > 1024 || strings.ContainsRune(typed, 0) {
				return false
			}
		case float64:
			if math.IsNaN(typed) || math.IsInf(typed, 0) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func (s *Service) devicePresence(ctx context.Context, value *Device) error {
	if s.presence == nil {
		return nil
	}
	online, err := s.presence.Online(ctx, value.TenantID, value.ID)
	if err != nil {
		return fail("PRESENCE_UNAVAILABLE", 503)
	}
	value.Online = &online
	return nil
}

func (s *Service) GetDevice(ctx context.Context, p Principal, id string) (Device, error) {
	if !uuidPattern.MatchString(id) {
		return Device{}, fail("INVALID_INPUT", 422)
	}
	tx, err := s.begin(ctx, p, false)
	if err != nil {
		return Device{}, err
	}
	defer rollback(tx)
	value, err := scanDevice(tx.QueryRow(ctx, "SELECT "+deviceColumns+" FROM devices WHERE tenant_id=$1 AND id=$2", p.tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Device{}, fail("DEVICE_NOT_FOUND", 404)
	}
	if err != nil {
		return Device{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	if err = s.devicePresence(ctx, &value); err != nil {
		return Device{}, err
	}
	return value, nil
}

// UpdateDevice applies only supplied mutable public properties. A null
// max_connections restores application inheritance; status/identity are immutable.
func (s *Service) UpdateDevice(ctx context.Context, p Principal, id string, input DeviceUpdate, key string) (Device, error) {
	if !uuidPattern.MatchString(id) || (input.DisplayName != nil && (utf8.RuneCountInString(*input.DisplayName) > 128 || strings.ContainsRune(*input.DisplayName, 0))) || (input.Metadata != nil && !validProperties(*input.Metadata)) || (input.Tags != nil && !validProperties(*input.Tags)) || (input.MaxConnections.Value != nil && (*input.MaxConnections.Value < -1 || *input.MaxConnections.Value > 2147483647)) {
		return Device{}, fail("INVALID_DEVICE_PROPERTIES", 422)
	}
	if input.DisplayName == nil && input.Metadata == nil && input.Tags == nil && input.Connectable == nil && !input.MaxConnections.Set {
		return Device{}, fail("EMPTY_PATCH", 422)
	}
	id = strings.ToLower(id)
	tx, err := s.begin(ctx, p, true)
	if err != nil {
		return Device{}, err
	}
	defer rollback(tx)
	var result Device
	request := struct {
		ID         string
		Properties DeviceUpdate
	}{id, input}
	found, kh, rh, err := s.prepareReplay(ctx, tx, p, "device.update", key, request, &result)
	if err != nil || found {
		return result, err
	}
	var metadata, tags []byte
	if input.Metadata != nil {
		metadata, _ = json.Marshal(*input.Metadata)
	}
	if input.Tags != nil {
		tags, _ = json.Marshal(*input.Tags)
	}
	result, err = scanDevice(tx.QueryRow(ctx, `UPDATE devices SET display_name=COALESCE($3,display_name),
metadata=COALESCE($4::jsonb,metadata),tags=COALESCE($5::jsonb,tags),connectable=COALESCE($6,connectable),
max_connections=CASE WHEN $7 THEN $8::integer ELSE max_connections END
WHERE tenant_id=$1 AND id=$2 RETURNING `+deviceColumns, p.tenantID, id, input.DisplayName, metadata, tags, input.Connectable, input.MaxConnections.Set, input.MaxConnections.Value))
	if errors.Is(err, pgx.ErrNoRows) {
		return Device{}, fail("DEVICE_NOT_FOUND", 404)
	}
	if err != nil {
		return Device{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	if err = s.finishMutation(ctx, tx, p, "device.update", "device", id, kh, rh, result); err != nil {
		return Device{}, err
	}
	if err = commit(ctx, tx); err != nil {
		return Device{}, err
	}
	return result, nil
}
