package authorization

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestExclusiveCanonicalEpochAndWireShape(t *testing.T) {
	for _, v := range []string{"1", "9223372036854775807"} {
		if !canonicalEpoch(v) {
			t.Fatal("valid epoch rejected")
		}
	}
	for _, v := range []string{"", "0", "01", "-1", "+1", "1.0", "9223372036854775808", "18446744073709551615"} {
		if canonicalEpoch(v) {
			t.Fatal("invalid epoch accepted")
		}
	}
	for _, exclusive := range []bool{false, true} {
		value := Session{ExclusiveTarget: exclusive}
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		if err = json.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"prepared", "target_fenced", "fence_required"} {
			_, exists := decoded[key]
			if exists != exclusive {
				t.Fatalf("wrong optional shape %s", key)
			}
		}
	}
	v := Session{ExclusiveTarget: true, TargetEpoch: "1"}
	if checkExclusiveAuthority(context.Background(), v, false) == nil {
		t.Fatal("missing epoch mutation allowed")
	}
	if err := checkExclusiveAuthority(context.Background(), v, true); err != nil {
		t.Fatal("initial read denied")
	}
	if checkExclusiveAuthority(WithExclusiveAuthority(context.Background(), "2", ""), v, true) == nil {
		t.Fatal("wrong epoch read allowed")
	}
}

type exclusiveOffsetRow struct{ at time.Time }

func (r exclusiveOffsetRow) Scan(dest ...any) error {
	for _, d := range dest {
		switch value := d.(type) {
		case *string:
			*value = "test"
		case *bool:
			*value = false
		case *int64:
			*value = 1
		case *time.Time:
			*value = r.at
		case **time.Time:
			copy := r.at
			*value = &copy
		}
	}
	return nil
}
func TestExclusiveNewDeadlinesSerializeUTCFromNonUTCDriver(t *testing.T) {
	at := time.Date(2026, 10, 29, 15, 30, 0, 123000000, time.FixedZone("fixture+0900", 9*3600))
	value, err := scanSession(exclusiveOffsetRow{at})
	if err != nil {
		t.Fatal(err)
	}
	if !value.ConnectDeadline.Equal(at) || !value.ReleaseNotBefore.Equal(at) {
		t.Fatal("normalization changed instant")
	}
	wire, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(wire, &fields); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"connect_deadline", "release_not_before"} {
		var timestamp string
		if err = json.Unmarshal(fields[field], &timestamp); err != nil || !strings.HasSuffix(timestamp, "Z") {
			t.Fatalf("%s not canonical UTC", field)
		}
	}
}
