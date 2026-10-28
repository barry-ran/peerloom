package relay

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgxpool"
)

type SharedNodeInput struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Region    string `json:"region"`
	Endpoint  string `json:"endpoint"`
	SecretRef string `json:"secret_ref"`
	Enabled   bool   `json:"enabled"`
}

// SetSharedNode is an offline database-operator boundary, never an HTTP method.
// Its caller must require explicit operator authority. Existing tenant nodes can
// never be adopted into the shared namespace by this upsert.
func SetSharedNode(ctx context.Context, pool *pgxpool.Pool, issuer *Issuer, input SharedNodeInput) error {
	if !uuidPattern.MatchString(input.ID) || strings.TrimSpace(input.Name) == "" || utf8.RuneCountInString(input.Name) > 128 || utf8.RuneCountInString(input.Region) > 64 || strings.ContainsRune(input.Name+input.Region, 0) {
		return failure("INVALID_RELAY_NODE", 422)
	}
	if input.Enabled {
		if err := issuer.ValidateNode("offline-operator", Node{SecretRef: input.SecretRef, URLs: []string{input.Endpoint}}); err != nil {
			return failure("RELAY_BINDING_NOT_APPROVED", 422)
		}
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return failure("DATABASE_UNAVAILABLE", 503)
	}
	defer rollback(tx)
	var revision int64
	err = tx.QueryRow(ctx, `INSERT INTO relay_nodes(id,tenant_id,name,region,endpoint,secret_ref,enabled)
VALUES($1,NULL,$2,$3,$4,$5,$6) ON CONFLICT(id) DO UPDATE SET
name=EXCLUDED.name,region=EXCLUDED.region,endpoint=EXCLUDED.endpoint,secret_ref=EXCLUDED.secret_ref,
enabled=EXCLUDED.enabled,revision=relay_nodes.revision+1 WHERE relay_nodes.tenant_id IS NULL RETURNING revision`, input.ID, input.Name, input.Region, input.Endpoint, input.SecretRef, input.Enabled).Scan(&revision)
	if err != nil {
		return failure("RELAY_OPERATOR_UPDATE_REJECTED", 409)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(actor_type,action,resource_type,resource_id,details)
VALUES('offline_operator','relay_node.shared_set','relay_node',$1,jsonb_build_object('revision',$2::bigint))`, input.ID, revision); err != nil {
		return failure("DATABASE_UNAVAILABLE", 503)
	}
	if err = tx.Commit(ctx); err != nil {
		return failure("COMMIT_UNCERTAIN_RETRY", 503)
	}
	return nil
}
