package management

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/barry-ran/peerloom/src/device-server/internal/authorization"
	"github.com/barry-ran/peerloom/src/device-server/internal/relay"
	"github.com/barry-ran/peerloom/src/device-server/internal/webhook"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Service struct {
	pool            *pgxpool.Pool
	aead            cipher.AEAD
	settings        Settings
	presence        Presence
	browser         BrowserAuthority
	relayIssuer     *relay.Issuer
	webhookRegistry *webhook.Registry
}

func New(pool *pgxpool.Pool, key []byte, settings Settings, presence ...Presence) (*Service, error) {
	if pool == nil || len(key) != 32 {
		return nil, errors.New("database and 32-byte management replay key required")
	}
	if err := settings.validate(); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(presence) > 1 {
		return nil, errors.New("at most one presence provider is supported")
	}
	service := &Service{pool: pool, aead: aead, settings: settings}
	if len(presence) == 1 {
		service.presence = presence[0]
	}
	return service, nil
}

func hash(value string) []byte {
	digest := sha256.Sum256([]byte(value))
	return digest[:]
}

func token(prefix string) (string, error) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return "", fail("INTERNAL_ERROR", 500)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(data), nil
}

func validText(value string, max int) bool {
	return strings.TrimSpace(value) != "" && utf8.RuneCountInString(value) <= max && !strings.ContainsRune(value, 0)
}

func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

func (s *Service) Authenticate(ctx context.Context, credential string) (Principal, error) {
	if !strings.HasPrefix(credential, "svc_") || len(credential) != 47 {
		return Principal{}, fail("SERVICE_AUTH_INVALID", 401)
	}
	var p Principal
	err := s.pool.QueryRow(ctx, `SELECT c.id::text,c.tenant_id::text,c.scope FROM tenant_service_credentials c
JOIN tenants t ON t.id=c.tenant_id WHERE c.credential_hash=$1 AND c.revoked_at IS NULL
AND c.expires_at>clock_timestamp() AND t.status='active'`, hash(credential)).Scan(&p.credentialID, &p.tenantID, &p.scope)
	if errors.Is(err, pgx.ErrNoRows) {
		return Principal{}, fail("SERVICE_AUTH_INVALID", 401)
	}
	if err != nil {
		return Principal{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	return p, nil
}

func (s *Service) begin(ctx context.Context, p Principal, admin bool) (pgx.Tx, error) {
	if !uuidPattern.MatchString(p.tenantID) || !uuidPattern.MatchString(p.credentialID) {
		return nil, fail("SERVICE_AUTH_INVALID", 401)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fail("DATABASE_UNAVAILABLE", 503)
	}
	// Serialize tenant mutations before acquiring any business row lock.
	if admin || p.browser != nil {
		if err = authorization.LockTenant(ctx, tx, p.tenantID); err != nil {
			rollback(tx)
			return nil, fail("DATABASE_UNAVAILABLE", 503)
		}
	}
	var scope Scope
	if p.browser != nil {
		if s.browser == nil {
			rollback(tx)
			return nil, fail("ADMIN_AUTH_INVALID", 401)
		}
		scope, err = s.browser.RevalidateBrowser(ctx, tx, *p.browser)
	} else {
		err = tx.QueryRow(ctx, `SELECT c.scope FROM tenant_service_credentials c JOIN tenants t ON t.id=c.tenant_id
WHERE c.id=$1 AND c.tenant_id=$2 AND c.revoked_at IS NULL AND c.expires_at>clock_timestamp()
AND t.status='active' FOR SHARE OF c,t`, p.credentialID, p.tenantID).Scan(&scope)
	}
	if err != nil {
		rollback(tx)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fail("SERVICE_AUTH_INVALID", 401)
		}
		var public *Error
		if errors.As(err, &public) {
			return nil, err
		}
		return nil, fail("DATABASE_UNAVAILABLE", 503)
	}

	if admin && scope != ScopeAdmin {
		rollback(tx)
		return nil, fail("SCOPE_REQUIRED", 403)
	}
	return tx, nil
}

func commit(ctx context.Context, tx pgx.Tx) error {
	if err := tx.Commit(ctx); err != nil {
		return fail("COMMIT_UNCERTAIN_RETRY_SAME_KEY", 503)
	}
	return nil
}

func recordAudit(ctx context.Context, tx pgx.Tx, tenant, actorType, actorID, action, resourceType, resourceID string, details any) error {
	encoded, err := json.Marshal(details)
	if err != nil {
		return fail("INTERNAL_ERROR", 500)
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,actor_type,actor_id,action,resource_type,resource_id,details)
VALUES($1,$2,$3,$4,$5,$6,$7)`, tenant, actorType, actorID, action, resourceType, resourceID, encoded)
	if err != nil {
		return fail("DATABASE_UNAVAILABLE", 503)
	}
	return nil
}
