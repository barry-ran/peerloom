package management

import (
	"encoding/json"
	"testing"
)

func TestRelayPatchRejectsNullUnknownAndKeepsFalse(t *testing.T) {
	for _, body := range []string{`null`, `{"enabled":null}`, `{"name":"ok","enabled":null}`, `{"secret":"forbidden"}`} {
		var input RelayNodeUpdate
		if err := json.Unmarshal([]byte(body), &input); err == nil {
			t.Fatal("invalid relay patch decoded")
		}
	}
	var input RelayNodeUpdate
	if err := json.Unmarshal([]byte(`{"enabled":false}`), &input); err != nil || input.Enabled == nil || *input.Enabled {
		t.Fatal("false patch was lost")
	}
}
