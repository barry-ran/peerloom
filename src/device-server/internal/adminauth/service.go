package adminauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/authorization"
	"github.com/barry-ran/peerloom/src/device-server/internal/management"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const SessionTTL = time.Hour

var userPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{2,63}$`)
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type Service struct {
	pool    *pgxpool.Pool
	hashing chan struct{}
	dummy   string
}
type Session struct {
	TenantID  string           `json:"tenant_id"`
	UserID    string           `json:"user_id"`
	SessionID string           `json:"-"`
	Username  string           `json:"username"`
	Scope     management.Scope `json:"scope"`
	CSRFToken string           `json:"csrf_token"`
	ExpiresAt time.Time        `json:"expires_at"`
}

func (Session) String() string   { return "[REDACTED browser session view]" }
func (Session) GoString() string { return "[REDACTED browser session view]" }

type LoginResult struct {
	Session Session
	Token   string
}

func (LoginResult) String() string          { return "[REDACTED browser session]" }
func (LoginResult) GoString() string        { return "[REDACTED browser session]" }
func problem(code string, status int) error { return &management.Error{Code: code, Status: status} }
func New(pool *pgxpool.Pool) (*Service, error) {
	if pool == nil {
		return nil, errors.New("database required")
	}
	dummy, err := randomToken("")
	if err != nil {
		return nil, err
	}
	encoded, err := HashPassword(dummy)
	if err != nil {
		return nil, errors.New("password hashing unavailable")
	}
	return &Service{pool: pool, hashing: make(chan struct{}, 4), dummy: encoded}, nil
}
func digest(value string) []byte { hash := sha256.Sum256([]byte(value)); return hash[:] }
func randomToken(prefix string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", problem("AUTH_UNAVAILABLE", 503)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}
func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
func (s *Service) Login(ctx context.Context, tenant, username, password, remoteIP string) (LoginResult, error) {
	select {
	case s.hashing <- struct{}{}:
		defer func() { <-s.hashing }()
	default:
		return LoginResult{}, problem("LOGIN_LIMITED", 429)
	}
	tenant = strings.ToLower(tenant)
	username = strings.ToLower(username)
	if len(username) > 64 || len(password) > 1024 || len(remoteIP) > 128 {
		return LoginResult{}, problem("AUTH_INVALID", 401)
	}
	if err := s.limit(ctx, tenant, username, remoteIP); err != nil {
		return LoginResult{}, err
	}
	encoded := s.dummy
	found := false
	var userID string
	if uuidPattern.MatchString(tenant) && userPattern.MatchString(username) {
		err := s.pool.QueryRow(ctx, `SELECT u.id::text,u.password_hash FROM admin_users u JOIN tenants t ON t.id=u.tenant_id WHERE u.tenant_id=$1 AND u.username=$2 AND u.enabled AND t.status='active'`, tenant, username).Scan(&userID, &encoded)
		if err == nil {
			found = true
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return LoginResult{}, problem("AUTH_UNAVAILABLE", 503)
		}
	}
	valid := verifyPassword(password, encoded)
	if !valid || !found {
		return LoginResult{}, problem("AUTH_INVALID", 401)
	}
	token, err := randomToken("adm_")
	if err != nil {
		return LoginResult{}, err
	}
	csrf, err := randomToken("")
	if err != nil {
		return LoginResult{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LoginResult{}, problem("AUTH_UNAVAILABLE", 503)
	}
	defer rollback(tx)
	if err = authorization.LockTenant(ctx, tx, tenant); err != nil {
		return LoginResult{}, problem("AUTH_UNAVAILABLE", 503)
	}
	var current string
	var scope management.Scope
	err = tx.QueryRow(ctx, `SELECT u.password_hash,u.scope FROM admin_users u JOIN tenants t ON t.id=u.tenant_id WHERE u.id=$1 AND u.tenant_id=$2 AND u.enabled AND t.status='active' FOR SHARE OF u,t`, userID, tenant).Scan(&current, &scope)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && current != encoded {
		return LoginResult{}, problem("AUTH_INVALID", 401)
	}
	if err != nil {
		return LoginResult{}, problem("AUTH_UNAVAILABLE", 503)
	}
	result := LoginResult{Token: token, Session: Session{TenantID: tenant, UserID: userID, Username: username, Scope: scope, CSRFToken: csrf}}
	err = tx.QueryRow(ctx, `INSERT INTO admin_sessions(tenant_id,user_id,token_hash,csrf_token,expires_at) VALUES($1,$2,$3,$4,clock_timestamp()+interval '1 hour') RETURNING id::text,expires_at`, tenant, userID, digest(token), csrf).Scan(&result.Session.SessionID, &result.Session.ExpiresAt)
	if err != nil {
		return LoginResult{}, problem("AUTH_UNAVAILABLE", 503)
	}
	if _, err = tx.Exec(ctx, `DELETE FROM admin_sessions WHERE id IN (SELECT id FROM admin_sessions WHERE user_id=$1 ORDER BY created_at DESC,id DESC OFFSET 10)`, userID); err != nil {
		return LoginResult{}, problem("AUTH_UNAVAILABLE", 503)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,actor_type,actor_id,action,resource_type,resource_id,details) VALUES($1,'admin_user',$2,'admin.login','admin_session',$3,'{}')`, tenant, userID, result.Session.SessionID); err != nil {
		return LoginResult{}, problem("AUTH_UNAVAILABLE", 503)
	}
	if err = tx.Commit(ctx); err != nil {
		return LoginResult{}, problem("AUTH_UNAVAILABLE", 503)
	}
	return result, nil
}
func (s *Service) limit(ctx context.Context, tenant, user, ip string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return problem("AUTH_UNAVAILABLE", 503)
	}
	defer rollback(tx)
	for _, entry := range []struct {
		key   string
		limit int
	}{{"global", 120}, {"ip:" + ip, 30}, {"user:" + tenant + ":" + user, 10}} {
		var count int
		err = tx.QueryRow(ctx, `INSERT INTO admin_login_windows(key_hash,window_start,attempts) VALUES($1,date_trunc('minute',clock_timestamp()),1) ON CONFLICT(key_hash,window_start) DO UPDATE SET attempts=least(admin_login_windows.attempts+1,121) RETURNING attempts`, digest(entry.key)).Scan(&count)
		if err != nil {
			return problem("AUTH_UNAVAILABLE", 503)
		}
		if count > entry.limit {
			if tx.Commit(ctx) != nil {
				return problem("AUTH_UNAVAILABLE", 503)
			}
			return problem("LOGIN_LIMITED", 429)
		}
	}
	if tx.Commit(ctx) != nil {
		return problem("AUTH_UNAVAILABLE", 503)
	}
	return nil
}
func (s *Service) Session(ctx context.Context, token string) (Session, error) {
	if !strings.HasPrefix(token, "adm_") || len(token) != 47 {
		return Session{}, problem("ADMIN_AUTH_INVALID", 401)
	}
	var result Session
	err := s.pool.QueryRow(ctx, `SELECT s.id::text,s.tenant_id::text,s.user_id::text,u.username,u.scope,s.csrf_token,s.expires_at FROM admin_sessions s JOIN admin_users u ON (u.id,u.tenant_id)=(s.user_id,s.tenant_id) JOIN tenants t ON t.id=s.tenant_id WHERE s.token_hash=$1 AND s.expires_at>clock_timestamp() AND u.enabled AND t.status='active'`, digest(token)).Scan(&result.SessionID, &result.TenantID, &result.UserID, &result.Username, &result.Scope, &result.CSRFToken, &result.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, problem("ADMIN_AUTH_INVALID", 401)
	}
	if err != nil {
		return Session{}, problem("AUTH_UNAVAILABLE", 503)
	}
	return result, nil
}
func (s *Service) Logout(ctx context.Context, token string) error {
	session, err := s.Session(ctx, token)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return problem("AUTH_UNAVAILABLE", 503)
	}
	defer rollback(tx)
	if err = authorization.LockTenant(ctx, tx, session.TenantID); err != nil {
		return problem("AUTH_UNAVAILABLE", 503)
	}
	if _, err = tx.Exec(ctx, `DELETE FROM admin_sessions WHERE id=$1 AND token_hash=$2`, session.SessionID, digest(token)); err != nil {
		return problem("AUTH_UNAVAILABLE", 503)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,actor_type,actor_id,action,resource_type,resource_id,details) VALUES($1,'admin_user',$2,'admin.logout','admin_session',$3,'{}')`, session.TenantID, session.UserID, session.SessionID); err != nil {
		return problem("AUTH_UNAVAILABLE", 503)
	}
	if tx.Commit(ctx) != nil {
		return problem("AUTH_UNAVAILABLE", 503)
	}
	return nil
}
