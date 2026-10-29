package relay

import (
	"context"
	"errors"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/authorization"
	"github.com/barry-ran/peerloom/src/device-server/internal/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Error struct {
	Code   string
	Status int
}

func (e *Error) Error() string              { return e.Code }
func failure(code string, status int) error { return &Error{Code: code, Status: status} }

type Limits struct {
	TenantPerMinute  int
	DevicePerMinute  int
	SessionPerMinute int
	RefreshMargin    time.Duration
}

func DefaultLimits() Limits {
	return Limits{TenantPerMinute: 0, DevicePerMinute: 0, SessionPerMinute: 0, RefreshMargin: 15 * time.Second}
}
func (l Limits) validate(ttl time.Duration) error {
	if l.TenantPerMinute < 0 || l.TenantPerMinute > 2147483647 || l.DevicePerMinute < 0 || l.DevicePerMinute > 2147483647 || l.SessionPerMinute < 0 || l.SessionPerMinute > 2147483647 || l.RefreshMargin < time.Second || l.RefreshMargin >= ttl/2 {
		return ErrConfiguration
	}
	return nil
}

type Service struct {
	pool          *pgxpool.Pool
	issuer        *Issuer
	authorization *authorization.Service
	limits        Limits
}

func NewService(pool *pgxpool.Pool, issuer *Issuer, authorization *authorization.Service, limits Limits) (*Service, error) {
	if pool == nil || issuer == nil || authorization == nil {
		return nil, ErrConfiguration
	}
	if err := limits.validate(issuer.ttl); err != nil {
		return nil, err
	}
	return &Service{pool: pool, issuer: issuer, authorization: authorization, limits: limits}, nil
}

type Response struct {
	TargetEpoch           string        `json:"target_epoch,omitempty"`
	SessionID             string        `json:"session_id"`
	NegotiationGeneration int           `json:"negotiation_generation"`
	ICEServers            []Credentials `json:"ice_servers"`
}

func (Response) String() string   { return "[REDACTED ICE response]" }
func (Response) GoString() string { return "[REDACTED ICE response]" }

type selectedNode struct {
	ID       string
	Revision int64
	Node     Node
}

func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
func bridgeError(err error) error {
	var domain *authorization.Error
	if errors.As(err, &domain) {
		return failure(domain.Code, domain.Status)
	}
	return failure("DATABASE_UNAVAILABLE", 503)
}

// IssueForSession linearizes authorization and issuance under the same tenant
// transaction lock. Every cache hit still checks the current session and node.
func (s *Service) IssueForSession(ctx context.Context, actor identity.Device, sessionID string) (Response, error) {
	return s.issueForSession(ctx, actor, sessionID, "")
}

// IssueAuthenticated rechecks and holds the actual bearer credential in the issuance transaction.
func (s *Service) IssueAuthenticated(ctx context.Context, actor identity.Device, sessionID, credential string) (Response, error) {
	if credential == "" {
		return Response{}, failure("AUTH_INVALID", 401)
	}
	return s.issueForSession(ctx, actor, sessionID, credential)
}

func (s *Service) issueForSession(ctx context.Context, actor identity.Device, sessionID, credential string) (Response, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Response{}, failure("DATABASE_UNAVAILABLE", 503)
	}
	defer rollback(tx)
	if err = authorization.LockTenant(ctx, tx, actor.TenantID); err != nil {
		return Response{}, bridgeError(err)
	}
	authorized, err := s.authorization.AuthorizeICEInTx(ctx, tx, actor, sessionID)
	if err != nil {
		return Response{}, bridgeError(err)
	}
	rows, err := tx.Query(ctx, `SELECT id::text,tenant_id::text,endpoint,secret_ref,revision FROM relay_nodes
WHERE enabled AND (tenant_id=$1 OR tenant_id IS NULL)
ORDER BY (tenant_id IS NULL),created_at,id LIMIT 4 FOR SHARE`, actor.TenantID)
	if err != nil {
		return Response{}, failure("DATABASE_UNAVAILABLE", 503)
	}
	nodes := make([]selectedNode, 0, 4)
	for rows.Next() {
		var node selectedNode
		var tenant, secretRef *string
		var endpoint string
		if err = rows.Scan(&node.ID, &tenant, &endpoint, &secretRef, &node.Revision); err != nil {
			rows.Close()
			return Response{}, failure("DATABASE_UNAVAILABLE", 503)
		}
		if tenant != nil {
			node.Node.TenantID = *tenant
		}
		if secretRef != nil {
			node.Node.SecretRef = *secretRef
		}
		node.Node.URLs = []string{endpoint}
		nodes = append(nodes, node)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return Response{}, failure("DATABASE_UNAVAILABLE", 503)
	}
	if credential != "" {
		if err = identity.AuthenticateCredentialInTx(ctx, tx, actor, credential); err != nil {
			return Response{}, err
		}
	}
	var now time.Time
	if err = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return Response{}, failure("DATABASE_UNAVAILABLE", 503)
	}
	if !authorized.LeaseExpiresAt.After(now) {
		return Response{}, failure("LEASE_EXPIRED", 403)
	}
	result := Response{TargetEpoch: authorized.TargetEpoch, SessionID: sessionID, NegotiationGeneration: int(authorized.NegotiationGeneration), ICEServers: make([]Credentials, 0, len(nodes))}
	for _, node := range nodes {
		if err = s.issuer.ValidateNode(actor.TenantID, node.Node); err != nil {
			return Response{}, failure("RELAY_CONFIGURATION_UNAVAILABLE", 503)
		}
		credential, err := s.issueNode(ctx, tx, actor, sessionID, authorized.NegotiationGeneration, node, now)
		if err != nil {
			return Response{}, err
		}
		result.ICEServers = append(result.ICEServers, credential)
	}
	// Row locks serialize revocation, but they do not freeze expiry time. Recheck
	// after all quota/receipt/audit work, immediately before the commit boundary.
	if credential != "" {
		if err = identity.AuthenticateCredentialInTx(ctx, tx, actor, credential); err != nil {
			return Response{}, err
		}
	}
	if err = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return Response{}, failure("DATABASE_UNAVAILABLE", 503)
	}
	if !authorized.LeaseExpiresAt.After(now) {
		return Response{}, failure("LEASE_EXPIRED", 403)
	}
	if err = tx.Commit(ctx); err != nil {
		return Response{}, failure("COMMIT_UNCERTAIN_RETRY", 503)
	}
	return result, nil
}

func (s *Service) issueNode(ctx context.Context, tx pgx.Tx, actor identity.Device, sessionID string, generation int64, node selectedNode, now time.Time) (Credentials, error) {
	var username, secretRef string
	var expires time.Time
	var revision int64
	err := tx.QueryRow(ctx, `SELECT username,expires_at,node_revision,secret_ref FROM relay_issuances
WHERE tenant_id=$1 AND device_id=$2 AND session_id=$3 AND node_id=$4 AND negotiation_generation=$5`, actor.TenantID, actor.ID, sessionID, node.ID, generation).Scan(&username, &expires, &revision, &secretRef)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Credentials{}, failure("DATABASE_UNAVAILABLE", 503)
	}
	if err == nil && revision == node.Revision && secretRef == node.Node.SecretRef && expires.After(now.Add(s.limits.RefreshMargin)) {
		credential, deriveErr := s.issuer.Derive(actor.TenantID, node.Node, username, expires, now)
		if deriveErr != nil {
			return Credentials{}, failure("RELAY_RECEIPT_UNAVAILABLE", 503)
		}
		return credential, nil
	}
	if err = s.charge(ctx, tx, actor, sessionID, now); err != nil {
		return Credentials{}, err
	}
	credential, err := s.issuer.Issue(actor.TenantID, actor.ID, sessionID, node.Node, now)
	if err != nil {
		return Credentials{}, failure("RELAY_UNAVAILABLE", 503)
	}
	_, err = tx.Exec(ctx, `INSERT INTO relay_issuances(tenant_id,device_id,session_id,node_id,negotiation_generation,node_revision,secret_ref,username,expires_at,created_at)
VALUES($1,$2,$3,$4,$10,$5,$6,$7,$8,$9)
ON CONFLICT(tenant_id,device_id,session_id,node_id,negotiation_generation) DO UPDATE SET
issuance_generation=EXCLUDED.issuance_generation,node_revision=EXCLUDED.node_revision,secret_ref=EXCLUDED.secret_ref,
username=EXCLUDED.username,expires_at=EXCLUDED.expires_at,created_at=EXCLUDED.created_at`, actor.TenantID, actor.ID, sessionID, node.ID, node.Revision, node.Node.SecretRef, credential.Username, credential.ExpiresAt, now, generation)
	if err != nil {
		return Credentials{}, failure("DATABASE_UNAVAILABLE", 503)
	}
	// Audit resource identifiers only; no TURN username/password or shared secret.
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,actor_type,actor_id,action,resource_type,resource_id,details)
VALUES($1,'device',$2,'relay.issue','session',$3,jsonb_build_object('node_id',$4::text))`, actor.TenantID, actor.ID, sessionID, node.ID)
	if err != nil {
		return Credentials{}, failure("DATABASE_UNAVAILABLE", 503)
	}
	return credential, nil
}

func (s *Service) charge(ctx context.Context, tx pgx.Tx, actor identity.Device, sessionID string, now time.Time) error {
	counters := []struct {
		scope, subject string
		limit          int
	}{
		{"tenant", actor.TenantID, s.limits.TenantPerMinute},
		{"device", actor.ID, s.limits.DevicePerMinute},
		{"session", sessionID, s.limits.SessionPerMinute},
	}
	for _, counter := range counters {
		if counter.limit == 0 {
			continue
		}
		var issued int
		err := tx.QueryRow(ctx, `INSERT INTO relay_issuance_windows(tenant_id,scope,subject_id,window_start,issued)
VALUES($1,$2,$3,$4,1) ON CONFLICT(tenant_id,scope,subject_id,window_start) DO UPDATE
SET issued=relay_issuance_windows.issued+1 WHERE relay_issuance_windows.issued<$5 RETURNING issued`, actor.TenantID, counter.scope, counter.subject, now.UTC().Truncate(time.Minute), counter.limit).Scan(&issued)
		if errors.Is(err, pgx.ErrNoRows) {
			return failure("RELAY_ISSUANCE_LIMIT", 429)
		}
		if err != nil {
			return failure("DATABASE_UNAVAILABLE", 503)
		}
	}
	return nil
}

// PurgeExpired performs two independently bounded batches. Rate windows survive
// well beyond the active minute; receipt cleanup cannot reset current counters.
func (s *Service) PurgeExpired(ctx context.Context) error {
	for _, query := range []string{
		`WITH doomed AS(SELECT ctid FROM relay_issuances WHERE expires_at<clock_timestamp()-interval '1 hour' ORDER BY expires_at LIMIT 256 FOR UPDATE SKIP LOCKED) DELETE FROM relay_issuances WHERE ctid IN(SELECT ctid FROM doomed)`,
		`WITH doomed AS(SELECT ctid FROM relay_issuance_windows WHERE window_start<clock_timestamp()-interval '2 minutes' ORDER BY window_start LIMIT 256 FOR UPDATE SKIP LOCKED) DELETE FROM relay_issuance_windows WHERE ctid IN(SELECT ctid FROM doomed)`,
	} {
		if _, err := s.pool.Exec(ctx, query); err != nil {
			return failure("DATABASE_UNAVAILABLE", 503)
		}
	}
	return nil
}
