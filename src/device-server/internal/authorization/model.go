// Package authorization owns grant-only session admission and bounded leases.
// Callers must supply a freshly server-authenticated identity, never payload claims.
package authorization

import (
	"context"
	"errors"
	"regexp"
	"time"
)

type Presence interface {
	Online(context.Context, string, string) (bool, error)
}

type Options struct {
	LeaseTTL        time.Duration
	ApprovalTimeout time.Duration
}

func DefaultOptions() Options {
	return Options{LeaseTTL: 60 * time.Second, ApprovalTimeout: 30 * time.Second}
}

func (o Options) validate() error {
	if o.LeaseTTL < time.Second || o.LeaseTTL > 5*time.Minute || o.ApprovalTimeout < time.Second || o.ApprovalTimeout > 2*time.Minute {
		return errors.New("authorization lease durations outside safe bounds")
	}
	return nil
}

type Session struct {
	ID                   string    `json:"session_id"`
	TenantID             string    `json:"tenant_id"`
	SourceDeviceID       string    `json:"source_device_id"`
	TargetDeviceID       string    `json:"target_device_id"`
	GrantID              string    `json:"grant_id"`
	State                string    `json:"state"`
	CloseReason          string    `json:"close_reason,omitempty"`
	LeaseExpiresAt       time.Time `json:"lease_expires_at"`
	SourceLeaseExpiresAt time.Time `json:"source_lease_expires_at"`
	TargetLeaseExpiresAt time.Time `json:"target_lease_expires_at"`
	LeaseGeneration      int64     `json:"lease_generation"`
	SourceConnected      bool      `json:"source_connected"`
	TargetConnected      bool      `json:"target_connected"`
	SourceOfferSeen      bool      `json:"source_offer_seen"`
	TargetAnswerSeen     bool      `json:"target_answer_seen"`
}

type Error struct {
	Code   string
	Status int
}

func (e *Error) Error() string              { return e.Code }
func failure(code string, status int) error { return &Error{Code: code, Status: status} }

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
