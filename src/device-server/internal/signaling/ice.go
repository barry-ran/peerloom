package signaling

import (
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"
)

var errICE = errors.New("invalid ICE batch")

const MaxICEPayloadBytes = 16384
const MaxICEBatchCandidates = 16

// Pointers distinguish absent/null fields from valid zero/false values.
type iceCandidate struct {
	Candidate        *string `json:"candidate"`
	SDPMid           *string `json:"sdp_mid"`
	SDPMLineIndex    *uint16 `json:"sdp_mline_index"`
	UsernameFragment *string `json:"username_fragment"`
}
type iceBatch struct {
	Candidates *[]iceCandidate `json:"candidates"`
	Complete   *bool           `json:"complete"`
}

func iceText(value *string, limit int) bool {
	return value != nil && len(*value) > 0 && len(*value) <= limit && utf8.ValidString(*value) && !strings.ContainsAny(*value, "\r\n\x00")
}
func decodeICE(data json.RawMessage) (iceBatch, int, error) {
	var batch iceBatch
	invalid := func() (iceBatch, int, error) { return iceBatch{}, 0, errICE }
	if len(data) > MaxICEPayloadBytes || !utf8.Valid(data) || !json.Valid(data) || decodePayload(data, &batch) != nil || batch.Candidates == nil || batch.Complete == nil {
		return invalid()
	}
	candidates := *batch.Candidates
	if len(candidates) > MaxICEBatchCandidates || (len(candidates) == 0 && !*batch.Complete) {
		return invalid()
	}
	size := 0
	for _, c := range candidates {
		if !iceText(c.Candidate, 4096) || !iceText(c.SDPMid, 256) || !iceText(c.UsernameFragment, 256) || c.SDPMLineIndex == nil {
			return invalid()
		}
		size += len(*c.Candidate) + len(*c.SDPMid) + len(*c.UsernameFragment)
	}
	return batch, size, nil
}
