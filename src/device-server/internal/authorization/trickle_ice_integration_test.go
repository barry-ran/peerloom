//go:build integration

package authorization

import (
	"sync"
	"testing"
)

func TestTrickleICEAuthorizationAndGeneration(t *testing.T) {
	f := setup(t)
	f.grant(t, 0, 1, "terminate", 4)
	value := f.request(t, 880)
	admit := func(peer int, gen int64, count int, complete bool) error {
		_, _, err := f.service.AuthorizeICEGeneration(f.ctx, f.peers[peer], value.ID, gen, count, count*60, complete)
		return err
	}
	code(t, admit(0, 1, 1, false), "DESCRIPTION_REQUIRED")
	code(t, admit(3, 1, 1, false), "SESSION_NOT_FOUND")
	_, err := f.service.AuthorizeDescriptionGeneration(f.ctx, f.peers[0], value.ID, "session.offer", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := admit(0, 1, 1, false); err != nil {
		t.Fatal(err)
	}
	code(t, admit(1, 1, 1, false), "DESCRIPTION_REQUIRED")
	_, err = f.service.AuthorizeDescriptionGeneration(f.ctx, f.peers[1], value.ID, "session.answer", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := admit(1, 1, 1, false); err != nil {
		t.Fatal(err)
	}
	code(t, admit(0, 2, 1, false), "NEGOTIATION_STALE")
	if err := admit(0, 1, 0, true); err != nil {
		t.Fatal(err)
	}
	if err := admit(0, 1, 0, true); err != nil {
		t.Fatal(err)
	}
	if err := admit(0, 1, 1, false); err != nil {
		t.Fatal(err)
	}
	_, deliver, err := f.service.AuthorizeICEGeneration(f.ctx, f.peers[0], value.ID, 1, 1, 60, false)
	if err != nil || deliver {
		t.Fatalf("late ICE must be ignored: deliver=%v err=%v", deliver, err)
	}
	_, deliver, err = f.service.AuthorizeICEGeneration(f.ctx, f.peers[0], value.ID, 1, 0, 0, true)
	if err != nil || deliver {
		t.Fatalf("repeated EOC must be ignored: deliver=%v err=%v", deliver, err)
	}
	token := f.credential(t, 0)
	f.exec(t, "UPDATE sessions SET negotiation_started_at=clock_timestamp()-interval '2 seconds' WHERE id=$1", value.ID)
	_, err = f.service.RecoverGeneration(f.ctx, f.peers[0], value.ID, token, 1)
	if err != nil {
		t.Fatal(err)
	}
	code(t, admit(0, 1, 1, false), "NEGOTIATION_STALE")
	code(t, admit(0, 2, 1, false), "DESCRIPTION_REQUIRED")
	_, err = f.service.AuthorizeDescriptionGeneration(f.ctx, f.peers[0], value.ID, "session.offer", 2)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 16; i++ {
		if err := admit(0, 2, 16, false); err != nil {
			t.Fatal(err)
		}
	}
	code(t, admit(0, 2, 1, false), "ICE_LIMIT")
	if err := admit(0, 2, 0, true); err != nil {
		t.Fatal(err)
	}
	_, err = f.service.Close(f.ctx, f.peers[0], value.ID, "CLIENT_CLOSED")
	if err != nil {
		t.Fatal(err)
	}
	code(t, admit(1, 2, 0, true), "SESSION_CLOSED")
}
func TestTrickleICEByteBudget(t *testing.T) {
	f := setup(t)
	f.grant(t, 0, 1, "terminate", 4)
	value := f.request(t, 881)
	_, err := f.service.AuthorizeDescriptionGeneration(f.ctx, f.peers[0], value.ID, "session.offer", 1)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 16; i++ {
		_, _, err = f.service.AuthorizeICEGeneration(f.ctx, f.peers[0], value.ID, 1, 4, 16384, false)
		if err != nil {
			t.Fatal(err)
		}
	}
	_, _, err = f.service.AuthorizeICEGeneration(f.ctx, f.peers[0], value.ID, 1, 1, 1, false)
	code(t, err, "ICE_LIMIT")
}

func TestTrickleICEConcurrentBudgetAndRevocation(t *testing.T) {
	f := setup(t)
	g := f.grant(t, 0, 1, "terminate", 4)
	value := f.request(t, 882)
	_, err := f.service.AuthorizeDescriptionGeneration(f.ctx, f.peers[0], value.ID, "session.offer", 1)
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, "UPDATE sessions SET source_ice_count=255 WHERE id=$1", value.ID)
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, e := f.service.AuthorizeICEGeneration(f.ctx, f.peers[0], value.ID, 1, 1, 60, false)
			results <- e
		}()
	}
	wg.Wait()
	close(results)
	success := 0
	for e := range results {
		if e == nil {
			success++
		} else {
			code(t, e, "ICE_LIMIT")
		}
	}
	if success != 1 {
		t.Fatalf("concurrent budget admitted %d", success)
	}
	if _, err = f.service.RevokeGrant(f.ctx, f.peers[0].TenantID, g); err != nil {
		t.Fatal(err)
	}
	_, _, err = f.service.AuthorizeICEGeneration(f.ctx, f.peers[0], value.ID, 1, 0, 0, true)
	code(t, err, "SESSION_CLOSED")
	var count int
	if err = f.pool.QueryRow(f.ctx, "SELECT source_ice_count FROM sessions WHERE id=$1", value.ID).Scan(&count); err != nil || count != 256 {
		t.Fatalf("budget mutated on denial: count=%d err=%v", count, err)
	}
}
