package signaling

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestICEWireValidation(t *testing.T) {
	c := `{"candidate":"candidate:1 1 udp 1 127.0.0.1 9 typ host","sdp_mid":"0","sdp_mline_index":0,"username_fragment":"uf"}`
	valid := `{"candidates":[` + c + `],"complete":false}`
	for _, input := range []string{valid, `{"candidates":[],"complete":true}`} {
		if _, _, err := decodeICE(json.RawMessage(input)); err != nil {
			t.Fatalf("valid: %v", err)
		}
	}
	for _, input := range []string{
		`{}`, `{"candidates":null,"complete":true}`, `{"candidates":[],"complete":false}`,
		`{"candidates":[],"complete":null}`, `{"candidates":[],"complete":true,"x":1}`,
		strings.Replace(valid, `"sdp_mid":"0"`, `"sdp_mid":null`, 1),
		strings.Replace(valid, `"sdp_mline_index":0`, `"sdp_mline_index":65536`, 1),
		strings.Replace(valid, `"sdp_mline_index":0`, `"sdp_mline_index":-1`, 1),
		strings.Replace(valid, `"username_fragment":"uf"`, `"username_fragment":""`, 1),
		`{"candidates":[` + strings.Repeat(c+`,`, 16) + c + `],"complete":false}`,
		strings.Replace(valid, `candidate:1`, strings.Repeat("x", 4097), 1),
		strings.Repeat(" ", 16385) + valid,
	} {
		if _, _, err := decodeICE(json.RawMessage(input)); err == nil {
			t.Fatalf("accepted invalid payload: %.100s", input)
		}
	}
}
