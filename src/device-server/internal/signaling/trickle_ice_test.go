package signaling

import (
	"context"
	"encoding/json"
	"github.com/barry-ran/peerloom/src/device-server/internal/identity"
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

func TestTrickleDescriptionsCannotBypassCandidateBudget(t *testing.T) {
	for _, sdp := range []string{
		"v=0\r\na=candidate:1 1 udp 1 127.0.0.1 9 typ host\r\n",
		"v=0\na=end-of-candidates\n", "a=candidate", "a=end-of-candidates:bad",
		"v=0\ra=candidate:1", "  a= Candidate:1\n", "a=END-OF-CANDIDATES",
	} {
		if trickleDescription(sdp) {
			t.Fatalf("accepted inline candidate/EOC: %q", sdp)
		}
	}
	for _, sdp := range []string{"v=0\r\na=ice-ufrag:test\r\na=ice-options:trickle\r\n", "s=a=candidate: is text\n", "a=x-candidate:test\n", "a=end-of-candidates-extension:yes\n"} {
		if !trickleDescription(sdp) {
			t.Fatalf("rejected unrelated SDP text: %q", sdp)
		}
	}
}

func TestInlineCandidatesRejectedBeforeAuthorizationMutation(t *testing.T) {
	for _, kind := range []string{"session.offer", "session.answer"} {
		payload, _ := json.Marshal(map[string]string{"sdp": "v=0\r\na=candidate:1 1 udp 1 127.0.0.1 9 typ host\r\n"})
		deliveries, err := AuthorizationDispatch(nil)(context.Background(), identity.Device{}, Envelope{Type: kind, SessionID: uuid(), Negotiation: 1, Payload: payload})
		if err == nil || len(deliveries) != 0 {
			t.Fatal("inline candidates reached authorization or forwarding")
		}
	}
}
