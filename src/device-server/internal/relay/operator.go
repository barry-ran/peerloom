package relay

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
	"unicode/utf8"
)

type SharedNodeInput struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Region    string  `json:"region"`
	Endpoint  string  `json:"endpoint"`
	SecretRef string  `json:"secret_ref"`
	Secret    *string `json:"secret,omitempty"`
	Enabled   bool    `json:"enabled"`
}

func (SharedNodeInput) String() string   { return "[REDACTED shared relay input]" }
func (SharedNodeInput) GoString() string { return "[REDACTED shared relay input]" }
func SetSharedNode(ctx context.Context, pool *pgxpool.Pool, issuer *Issuer, input SharedNodeInput) error {
	if !uuidPattern.MatchString(input.ID) || strings.TrimSpace(input.Name) == "" || utf8.RuneCountInString(input.Name) > 128 || utf8.RuneCountInString(input.Region) > 64 || strings.ContainsRune(input.Name+input.Region, 0) || input.SecretRef != "" {
		return failure("INVALID_RELAY_NODE", 422)
	}
	if err := issuer.ValidateEndpoint(input.Endpoint); err != nil {
		return err
	}
	if input.Secret != nil {
		if err := issuer.ValidateConfiguration(input.Endpoint, *input.Secret); err != nil {
			return err
		}
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return failure("DATABASE_UNAVAILABLE", 503)
	}
	defer rollback(tx)
	if err = LockConfiguration(ctx, tx); err != nil {
		return err
	}
	var tenant *string
	var version int64
	err = tx.QueryRow(ctx, "SELECT tenant_id::text,secret_version FROM relay_nodes WHERE id=$1 FOR UPDATE", input.ID).Scan(&tenant, &version)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return failure("DATABASE_UNAVAILABLE", 503)
	}
	if tenant != nil {
		return failure("RELAY_OPERATOR_UPDATE_REJECTED", 409)
	}
	if version == 0 && input.Secret == nil {
		return failure("RELAY_CONFIGURATION_REQUIRED", 422)
	}
	var revision int64
	err = tx.QueryRow(ctx, `INSERT INTO relay_nodes(id,tenant_id,name,region,endpoint,secret_ref,enabled)
VALUES($1,NULL,$2,$3,$4,NULL,$5) ON CONFLICT(id) DO UPDATE SET
name=EXCLUDED.name,region=EXCLUDED.region,endpoint=EXCLUDED.endpoint,enabled=EXCLUDED.enabled,
revision=relay_nodes.revision+1 WHERE relay_nodes.tenant_id IS NULL RETURNING revision`, input.ID, input.Name, input.Region, input.Endpoint, input.Enabled).Scan(&revision)
	if err != nil {
		return failure("RELAY_OPERATOR_UPDATE_REJECTED", 409)
	}
	if input.Secret != nil {
		version++
		if err = issuer.StoreSecret(ctx, tx, input.ID, "", *input.Secret, version); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "UPDATE relay_nodes SET secret_version=$2 WHERE id=$1", input.ID, version); err != nil {
			return failure("DATABASE_UNAVAILABLE", 503)
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(actor_type,action,resource_type,resource_id,details)
VALUES('offline_operator','relay_node.shared_set','relay_node',$1,jsonb_build_object('revision',$2::bigint,'secret_version',$3::bigint))`, input.ID, revision, version); err != nil {
		return failure("DATABASE_UNAVAILABLE", 503)
	}
	if err = tx.Commit(ctx); err != nil {
		return failure("COMMIT_UNCERTAIN_RETRY", 503)
	}
	return nil
}
