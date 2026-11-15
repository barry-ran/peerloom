//go:build integration

package management

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"github.com/barry-ran/peerloom/src/device-server/internal/relay"
	"strings"
	"sync"
	"testing"
	"time"
)

func matchesTURN(c relay.Credentials, secret string) bool {
	m := hmac.New(sha1.New, []byte(secret))
	m.Write([]byte(c.Username))
	return hmac.Equal([]byte(c.Credential), []byte(base64.StdEncoding.EncodeToString(m.Sum(nil))))
}
func TestRelayEmptySnapshotRemainsEmptyUntilNewSession(t *testing.T) {
	f := setup(t)
	issuer := setupRelay(t, f)
	pair := makePair(t, f)
	service, err := relay.NewService(f.pool, issuer, pair.auth, relay.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	session, err := pair.auth.Request(f.ctx, pair.actors[0], pair.actors[1].ID, "00000000-0000-0000-0000-000000000201")
	if err != nil {
		t.Fatal(err)
	}
	r, err := service.IssueForSession(f.ctx, pair.actors[0], session.ID)
	if err != nil || len(r.ICEServers) != 0 {
		t.Fatal("empty snapshot failed")
	}
	if _, err = f.service.CreateRelayNode(f.ctx, f.principal, relayInput(), "snapshot-create"); err != nil {
		t.Fatal(err)
	}
	r, err = service.IssueForSession(f.ctx, pair.actors[1], session.ID)
	if err != nil || len(r.ICEServers) != 0 {
		t.Fatal("second peer adopted new config")
	}
	if _, err = pair.auth.Close(f.ctx, pair.actors[0], session.ID, "normal"); err != nil {
		t.Fatal(err)
	}
	fresh, err := pair.auth.Request(f.ctx, pair.actors[0], pair.actors[1].ID, "00000000-0000-0000-0000-000000000202")
	if err != nil {
		t.Fatal(err)
	}
	r, err = service.IssueForSession(f.ctx, pair.actors[0], fresh.ID)
	if err != nil || len(r.ICEServers) != 1 {
		t.Fatal("new session missing new config")
	}
}
func TestRelayRotationKeepsBothPeersSnapshotAndReceipts(t *testing.T) {
	f := setup(t)
	issuer := setupRelay(t, f)
	pair := makePair(t, f)
	node, err := f.service.CreateRelayNode(f.ctx, f.principal, relayInput(), "rotation-create")
	if err != nil {
		t.Fatal(err)
	}
	service, err := relay.NewService(f.pool, issuer, pair.auth, relay.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	session, err := pair.auth.Request(f.ctx, pair.actors[0], pair.actors[1].ID, "00000000-0000-0000-0000-000000000203")
	if err != nil {
		t.Fatal(err)
	}
	before, err := service.IssueForSession(f.ctx, pair.actors[0], session.ID)
	if err != nil {
		t.Fatal(err)
	}
	patch := RelayNodeUpdate{Secret: ptr(strings.Repeat("n", 32)), Endpoint: ptr("turn:new.example.com:3478?transport=udp")}
	updated, err := f.service.UpdateRelayNode(f.ctx, f.principal, node.ID, patch, "rotate-once")
	if err != nil || updated.SecretVersion != 2 {
		t.Fatal("rotation failed")
	}
	again, err := f.service.UpdateRelayNode(f.ctx, f.principal, node.ID, patch, "rotate-once")
	if err != nil || again.SecretVersion != 2 {
		t.Fatal("retry rotated twice")
	}
	encoded, _ := json.Marshal(updated)
	if strings.Contains(string(encoded), strings.Repeat("n", 32)) {
		t.Fatal("response leaked secret")
	}
	var count int
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM relay_secret_versions WHERE node_id=$1", node.ID).Scan(&count); err != nil || count != 2 {
		t.Fatal("version count")
	}
	other, err := service.IssueForSession(f.ctx, pair.actors[1], session.ID)
	if err != nil || len(other.ICEServers) != 1 || other.ICEServers[0].URLs[0] != before.ICEServers[0].URLs[0] || !matchesTURN(other.ICEServers[0], strings.Repeat("s", 32)) {
		t.Fatal("two peers received different configuration")
	}
	repeated, err := service.IssueForSession(f.ctx, pair.actors[0], session.ID)
	if err != nil || repeated.ICEServers[0].Credential != before.ICEServers[0].Credential {
		t.Fatal("old receipt changed after rotation")
	}
	// Disabling configuration is not revocation: existing authorized sessions retain it.
	if _, err = f.service.UpdateRelayNode(f.ctx, f.principal, node.ID, RelayNodeUpdate{Enabled: ptr(false)}, "disable-current"); err != nil {
		t.Fatal(err)
	}
	if _, err = service.IssueForSession(f.ctx, pair.actors[0], session.ID); err != nil {
		t.Fatal("disable invalidated existing snapshot")
	}
	if _, err = f.service.UpdateRelayNode(f.ctx, f.principal, node.ID, RelayNodeUpdate{Enabled: ptr(true)}, "enable-new"); err != nil {
		t.Fatal(err)
	}
	if _, err = pair.auth.Close(f.ctx, pair.actors[0], session.ID, "normal"); err != nil {
		t.Fatal(err)
	}
	fresh, err := pair.auth.Request(f.ctx, pair.actors[0], pair.actors[1].ID, "00000000-0000-0000-0000-000000000204")
	if err != nil {
		t.Fatal(err)
	}
	current, err := service.IssueForSession(f.ctx, pair.actors[0], fresh.ID)
	if err != nil || current.ICEServers[0].URLs[0] != *patch.Endpoint || !matchesTURN(current.ICEServers[0], *patch.Secret) {
		t.Fatal("new session missed new config")
	}
	wrong, err := relay.NewDatabaseIssuer([]byte(strings.Repeat("w", 32)), 5*time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	restarted, _ := relay.NewService(f.pool, wrong, pair.auth, relay.DefaultLimits())
	if _, err = restarted.IssueForSession(f.ctx, pair.actors[0], fresh.ID); err == nil {
		t.Fatal("wrong master key accepted cached receipt")
	}
	if _, err = f.pool.Exec(f.ctx, "UPDATE relay_secret_versions SET ciphertext=set_byte(ciphertext,0,get_byte(ciphertext,0)#1) WHERE node_id=$1 AND version=2", node.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = service.IssueForSession(f.ctx, pair.actors[0], fresh.ID); err == nil {
		t.Fatal("corrupt encrypted secret accepted")
	}
}
func TestRelayConcurrentPeersAndRotationSelectOneSnapshot(t *testing.T) {
	f := setup(t)
	issuer := setupRelay(t, f)
	pair := makePair(t, f)
	node, err := f.service.CreateRelayNode(f.ctx, f.principal, relayInput(), "race-create")
	if err != nil {
		t.Fatal(err)
	}
	session, err := pair.auth.Request(f.ctx, pair.actors[0], pair.actors[1].ID, "00000000-0000-0000-0000-000000000205")
	if err != nil {
		t.Fatal(err)
	}
	service, _ := relay.NewService(f.pool, issuer, pair.auth, relay.DefaultLimits())
	start := make(chan struct{})
	var wg sync.WaitGroup
	var responses [2]relay.Response
	var errs [3]error
	for n := 0; n < 2; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start
			responses[n], errs[n] = service.IssueForSession(f.ctx, pair.actors[n], session.ID)
		}(n)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		_, errs[2] = f.service.UpdateRelayNode(f.ctx, f.principal, node.ID, RelayNodeUpdate{Secret: ptr(strings.Repeat("z", 32))}, "race-rotate")
	}()
	close(start)
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	for _, secret := range []string{strings.Repeat("s", 32), strings.Repeat("z", 32)} {
		if matchesTURN(responses[0].ICEServers[0], secret) != matchesTURN(responses[1].ICEServers[0], secret) {
			t.Fatal("concurrent peers split secret versions")
		}
	}
	var snapshots int
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM relay_session_snapshots WHERE session_id=$1", session.ID).Scan(&snapshots); err != nil || snapshots != 1 {
		t.Fatal("not exactly one snapshot")
	}
}
