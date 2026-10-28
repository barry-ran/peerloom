package identity

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/tenantlock"
	"github.com/jackc/pgx/v5"
)

func validDirectKey(key string) bool {
	if len(key) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(key)
	return err == nil && len(key) == 43 && len(decoded) == 32
}

// RegisterDirect is unauthenticated enrollment, not proof of installation-key
// possession. The random recovery key is a temporary bearer secret. Never log it.
func (s *Store) RegisterDirect(ctx context.Context, input Registration, key, remoteIP string) (Credential, error) {
	address, err := netip.ParseAddr(remoteIP)
	if err != nil || address.Zone() != "" {
		return Credential{}, Fail("INVALID_REMOTE_ADDRESS", 422)
	}
	address = address.Unmap()
	source := address.String()
	// IPv6 privacy addresses share a /64 budget instead of minting unlimited keys.
	if address.Is6() {
		source = netip.PrefixFrom(address, 64).Masked().String()
	}
	if err = s.directAdmission(ctx, []directBucket{{"global", s.settings.DirectGlobalPerMinute}, {"ip:" + source, s.settings.DirectIPPerMinute}}); err != nil {
		return Credential{}, err
	}
	if err = input.validate(true); err != nil {
		return Credential{}, err
	}
	if !validDirectKey(key) {
		return Credential{}, Fail("DIRECT_RECOVERY_KEY_REQUIRED", 422)
	}
	input.ApplicationID = strings.ToLower(input.ApplicationID)
	var tenant, mode string
	var enabled bool
	err = s.pool.QueryRow(ctx, `SELECT a.tenant_id::text,a.registration_mode,a.enabled AND t.status='active' FROM applications a JOIN tenants t ON t.id=a.tenant_id WHERE a.id=$1`, input.ApplicationID).Scan(&tenant, &mode, &enabled)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (!enabled || mode != "direct") {
		return Credential{}, Fail("DIRECT_REGISTRATION_DISABLED", 403)
	}
	if err != nil {
		return Credential{}, Fail("DATABASE_UNAVAILABLE", 503)
	}
	if err = s.directAdmission(ctx, []directBucket{{"app:" + input.ApplicationID, s.settings.DirectAppPerMinute}}); err != nil {
		return Credential{}, err
	}
	canonical, err := json.Marshal(input)
	if err != nil {
		return Credential{}, Fail("INVALID_INPUT", 422)
	}
	keyHash, requestHash := digest(key), digest(string(canonical))
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Credential{}, Fail("DATABASE_UNAVAILABLE", 503)
	}
	defer rollback(tx)
	if err = tenantlock.Acquire(ctx, tx, tenant); err != nil {
		return Credential{}, Fail("DATABASE_UNAVAILABLE", 503)
	}
	// Lock order matches management; application exclusion also serializes the
	// existing grant path when an operator switches an application between modes.
	err = tx.QueryRow(ctx, `SELECT a.registration_mode,a.enabled AND t.status='active' FROM applications a JOIN tenants t ON t.id=a.tenant_id WHERE a.id=$1 AND a.tenant_id=$2 FOR UPDATE OF a FOR SHARE OF t`, input.ApplicationID, tenant).Scan(&mode, &enabled)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (!enabled || mode != "direct") {
		return Credential{}, Fail("DIRECT_REGISTRATION_DISABLED", 403)
	}
	if err != nil {
		return Credential{}, Fail("DATABASE_UNAVAILABLE", 503)
	}
	var storedHash []byte
	err = tx.QueryRow(ctx, `SELECT request_hash FROM direct_registration_receipts WHERE application_id=$1 AND key_hash=$2`, input.ApplicationID, keyHash).Scan(&storedHash)
	scope := "direct:" + input.ApplicationID
	if err == nil {
		if subtle.ConstantTimeCompare(storedHash, requestHash) != 1 {
			return Credential{}, Fail("IDEMPOTENCY_CONFLICT", 409)
		}
		value, found, err := s.loadReplay(ctx, tx, tenant, "registration", scope, keyHash, requestHash)
		if err != nil {
			return Credential{}, err
		}
		if !found {
			return Credential{}, Fail("REPLAY_EXPIRED", 409)
		}
		return value, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Credential{}, Fail("DATABASE_UNAVAILABLE", 503)
	}
	var total, daily int
	err = tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM devices WHERE application_id=$1 AND tenant_id=$2),(SELECT count(*) FROM direct_registration_receipts WHERE application_id=$1 AND created_at>=date_trunc('day',clock_timestamp() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')`, input.ApplicationID, tenant).Scan(&total, &daily)
	if err != nil {
		return Credential{}, Fail("DATABASE_UNAVAILABLE", 503)
	}
	if total >= s.settings.DirectAppDevices || daily >= s.settings.DirectAppPerDay {
		return Credential{}, Fail("REGISTRATION_QUOTA_EXCEEDED", 429)
	}
	metadata := input.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadataJSON, _ := json.Marshal(metadata)
	var deviceID string
	err = tx.QueryRow(ctx, `INSERT INTO devices(tenant_id,application_id,installation_key_hash,platform,sdk_version,metadata) VALUES($1,$2,$3,$4,$5,$6) RETURNING id::text`, tenant, input.ApplicationID, digest(input.InstallationPublicKey), input.Platform, input.SDKVersion, metadataJSON).Scan(&deviceID)
	if err != nil {
		return Credential{}, Fail("DATABASE_UNAVAILABLE", 503)
	}
	var now time.Time
	if err = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return Credential{}, Fail("DATABASE_UNAVAILABLE", 503)
	}
	result, err := s.issue(ctx, tx, tenant, deviceID, now)
	if err != nil {
		return Credential{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO direct_registration_receipts(tenant_id,application_id,key_hash,request_hash,device_id) VALUES($1,$2,$3,$4,$5)`, tenant, input.ApplicationID, keyHash, requestHash, deviceID); err != nil {
		return Credential{}, Fail("DATABASE_UNAVAILABLE", 503)
	}
	if err = s.saveReplay(ctx, tx, tenant, "registration", scope, keyHash, requestHash, result, now.Add(s.settings.ReplayTTL)); err != nil {
		return Credential{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,actor_type,actor_id,action,resource_type,resource_id,details) VALUES($1,'device',$2,'device.register.direct','device',$2,'{}')`, tenant, deviceID); err != nil {
		return Credential{}, Fail("DATABASE_UNAVAILABLE", 503)
	}
	if err = tx.Commit(ctx); err != nil {
		return Credential{}, Fail("COMMIT_UNCERTAIN_RETRY_SAME_KEY", 503)
	}
	return result, nil
}

type directBucket struct {
	key   string
	limit int
}

// Admission persists independently of enrollment success or rollback, including
// retries. Global-first ordering bounds new IP-counter cardinality and lock order.
func (s *Store) directAdmission(ctx context.Context, buckets []directBucket) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Fail("DATABASE_UNAVAILABLE", 503)
	}
	defer rollback(tx)
	limited := false
	for _, bucket := range buckets {
		var attempts int
		err = tx.QueryRow(ctx, `INSERT INTO direct_registration_windows(key_hash,window_start,attempts) VALUES($1,date_trunc('minute',clock_timestamp()),1) ON CONFLICT(key_hash,window_start) DO UPDATE SET attempts=LEAST(direct_registration_windows.attempts+1,6001) RETURNING attempts`, digest("peerloom-direct:"+bucket.key)).Scan(&attempts)
		if err != nil {
			return Fail("DATABASE_UNAVAILABLE", 503)
		}
		if attempts > bucket.limit {
			limited = true
			break
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return Fail("DATABASE_UNAVAILABLE", 503)
	}
	if limited {
		return Fail("REGISTRATION_RATE_LIMITED", 429)
	}
	return nil
}
