package signaling

import (
	"encoding/json"
	"testing"
	"time"
)

func TestExclusiveEpochEnvelopeCanonicalString(t *testing.T) {
	base := map[string]any{"v": 1, "type": "session.fence_ack", "id": uuid(), "session_id": uuid(), "seq": 1, "sent_at": time.Now().UTC().Format(time.RFC3339Nano), "payload": map[string]any{}}
	for _, v := range []any{"1", "9223372036854775807"} {
		base["target_epoch"] = v
		wire, _ := json.Marshal(base)
		if _, err := Decode(wire); err != nil {
			t.Fatal("canonical epoch rejected", err)
		}
	}
	for _, v := range []any{"", "0", "01", "-1", "9223372036854775808", 1, nil} {
		base["target_epoch"] = v
		wire, _ := json.Marshal(base)
		if _, err := Decode(wire); err == nil {
			t.Fatal("noncanonical epoch accepted")
		}
	}
	delete(base, "target_epoch")
	base["type"] = "sync.request"
	wire, _ := json.Marshal(base)
	if _, err := Decode(wire); err != nil {
		t.Fatal("initial read envelope denied")
	}
}
