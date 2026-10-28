// Package signaling implements authenticated, fenced native WebSocket signaling.
package signaling

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"
)

const MaxFrameBytes = 128 << 10

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type Envelope struct {
	Version     int             `json:"v"`
	Type        string          `json:"type"`
	ID          string          `json:"id"`
	RequestID   string          `json:"request_id,omitempty"`
	SessionID   string          `json:"session_id,omitempty"`
	Generation  int64           `json:"connection_generation,omitempty"`
	Fence       string          `json:"fencing_token,omitempty"`
	Negotiation int64           `json:"negotiation_generation,omitempty"`
	Seq         int64           `json:"seq"`
	SentAt      string          `json:"sent_at"`
	Payload     json.RawMessage `json:"payload"`
}

func Decode(data []byte) (Envelope, error) {
	var e Envelope
	if len(data) > MaxFrameBytes {
		return e, errors.New("frame too large")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&e); err != nil {
		return e, errors.New("invalid envelope")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return e, errors.New("trailing value")
	}
	if e.Version != 1 || !uuidPattern.MatchString(e.ID) || e.Seq < 0 || e.Seq > 9007199254740991 || len(e.Type) > 64 {
		return e, errors.New("invalid envelope")
	}
	if e.SessionID != "" && !uuidPattern.MatchString(e.SessionID) {
		return e, errors.New("invalid session")
	}
	if e.RequestID != "" && !uuidPattern.MatchString(e.RequestID) {
		return e, errors.New("invalid request")
	}
	// Only omission is legacy-compatible. Explicit zero or null must not be
	// silently interpreted as a missing generation by encoding/json.
	var presence struct {
		Negotiation json.RawMessage `json:"negotiation_generation"`
	}
	if err := json.Unmarshal(data, &presence); err != nil || (len(presence.Negotiation) != 0 && e.Negotiation == 0) {
		return e, errors.New("invalid negotiation generation")
	}
	if e.Generation < 0 || e.Generation > 9007199254740991 || e.Negotiation < 0 || e.Negotiation > 9007199254740991 || len(e.Fence) > 256 {
		return e, errors.New("invalid generation")
	}
	if len(e.SentAt) == 0 || e.SentAt[len(e.SentAt)-1] != 'Z' {
		return e, errors.New("invalid timestamp")
	}
	if _, err := time.Parse(time.RFC3339Nano, e.SentAt); err != nil {
		return e, errors.New("invalid timestamp")
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(e.Payload, &payload); err != nil || payload == nil || len(payload) > 32 {
		return e, errors.New("invalid payload")
	}
	return e, nil
}
func EmptyPayload(e Envelope) bool {
	var payload map[string]json.RawMessage
	return json.Unmarshal(e.Payload, &payload) == nil && payload != nil && len(payload) == 0
}
