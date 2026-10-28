package management

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/relay"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NewWithRelay binds the immutable operator registry before HTTP handlers exist.
func NewWithRelay(pool *pgxpool.Pool, key []byte, settings Settings, presence Presence, issuer *relay.Issuer) (*Service, error) {
	service, err := New(pool, key, settings, presence)
	if err != nil {
		return nil, err
	}
	service.relayIssuer = issuer
	return service, nil
}

type RelayNode struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Name      string    `json:"name"`
	Region    string    `json:"region"`
	Endpoint  string    `json:"endpoint"`
	SecretRef string    `json:"secret_ref"`
	Enabled   bool      `json:"enabled"`
	Revision  int64     `json:"revision"`
	CreatedAt time.Time `json:"created_at"`
}
type RelayNodeInput struct {
	Name      string `json:"name"`
	Region    string `json:"region"`
	Endpoint  string `json:"endpoint"`
	SecretRef string `json:"secret_ref"`
}
type RelayNodeUpdate struct {
	Name      *string `json:"name"`
	Region    *string `json:"region"`
	Endpoint  *string `json:"endpoint"`
	SecretRef *string `json:"secret_ref"`
	Enabled   *bool   `json:"enabled"`
}
type RelayNodePage struct {
	Items      []RelayNode `json:"items"`
	NextCursor string      `json:"next_cursor,omitempty"`
}

var relayReferencePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

const relayColumns = "id::text,tenant_id::text,name,coalesce(region,''),endpoint,coalesce(secret_ref,''),enabled,revision,created_at"

func scanRelay(row scanner) (RelayNode, error) {
	var value RelayNode
	err := row.Scan(&value.ID, &value.TenantID, &value.Name, &value.Region, &value.Endpoint, &value.SecretRef, &value.Enabled, &value.Revision, &value.CreatedAt)
	return value, err
}
func (s *Service) validateRelay(tenant string, input RelayNodeInput) error {
	if !validText(input.Name, 128) || (input.Region != "" && !validText(input.Region, 64)) {
		return fail("INVALID_RELAY_NODE", 422)
	}
	if s.relayIssuer == nil {
		return fail("RELAY_CONFIGURATION_UNAVAILABLE", 503)
	}
	node := relay.Node{TenantID: tenant, SecretRef: input.SecretRef, URLs: []string{input.Endpoint}}
	if err := s.relayIssuer.ValidateNode(tenant, node); err != nil {
		return fail("RELAY_BINDING_NOT_APPROVED", 422)
	}
	return nil
}
func (s *Service) CreateRelayNode(ctx context.Context, p Principal, input RelayNodeInput, key string) (RelayNode, error) {
	if err := s.validateRelay(p.tenantID, input); err != nil {
		return RelayNode{}, err
	}
	tx, err := s.begin(ctx, p, true)
	if err != nil {
		return RelayNode{}, err
	}
	defer rollback(tx)
	var result RelayNode
	found, keyHash, requestHash, err := s.prepareReplay(ctx, tx, p, "relay_node.create", key, input, &result)
	if err != nil {
		return RelayNode{}, err
	}
	if found {
		return result, nil
	}
	result, err = scanRelay(tx.QueryRow(ctx, `INSERT INTO relay_nodes(tenant_id,name,region,endpoint,secret_ref) VALUES($1,$2,$3,$4,$5) RETURNING `+relayColumns, p.tenantID, input.Name, input.Region, input.Endpoint, input.SecretRef))
	if err != nil {
		return RelayNode{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	if err = s.finishRelay(ctx, tx, p, "relay_node.create", result, keyHash, requestHash, 201); err != nil {
		return RelayNode{}, err
	}
	return result, nil
}
func (s *Service) finishRelay(ctx context.Context, tx pgx.Tx, p Principal, operation string, result RelayNode, keyHash, requestHash []byte, status int) error {
	if err := recordAudit(ctx, tx, p.tenantID, p.actorType(), p.credentialID, operation, "relay_node", result.ID, map[string]any{"revision": result.Revision}); err != nil {
		return err
	}
	if err := s.saveReplay(ctx, tx, p, operation, result.ID, status, keyHash, requestHash, result, nil); err != nil {
		return err
	}
	return commit(ctx, tx)
}
func (s *Service) UpdateRelayNode(ctx context.Context, p Principal, id string, input RelayNodeUpdate, key string) (RelayNode, error) {
	if !uuidPattern.MatchString(id) || (input.Name == nil && input.Region == nil && input.Endpoint == nil && input.SecretRef == nil && input.Enabled == nil) {
		return RelayNode{}, fail("INVALID_RELAY_PATCH", 422)
	}
	tx, err := s.begin(ctx, p, true)
	if err != nil {
		return RelayNode{}, err
	}
	defer rollback(tx)
	var result RelayNode
	operation := "relay_node.update:" + strings.ToLower(id)
	found, keyHash, requestHash, err := s.prepareReplay(ctx, tx, p, operation, key, input, &result)
	if err != nil {
		return RelayNode{}, err
	}
	if found {
		return result, nil
	}
	result, err = scanRelay(tx.QueryRow(ctx, "SELECT "+relayColumns+" FROM relay_nodes WHERE tenant_id=$1 AND id=$2 FOR UPDATE", p.tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return RelayNode{}, fail("RELAY_NODE_NOT_FOUND", 404)
	}
	if err != nil {
		return RelayNode{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	if input.Name != nil {
		result.Name = *input.Name
	}
	if input.Region != nil {
		result.Region = *input.Region
	}
	if input.Endpoint != nil {
		result.Endpoint = *input.Endpoint
	}
	if input.SecretRef != nil {
		result.SecretRef = *input.SecretRef
	}
	if input.Enabled != nil {
		result.Enabled = *input.Enabled
	}
	if !validText(result.Name, 128) || (result.Region != "" && !validText(result.Region, 64)) || !validText(result.Endpoint, 2048) || !relayReferencePattern.MatchString(result.SecretRef) {
		return RelayNode{}, fail("INVALID_RELAY_NODE", 422)
	}
	if result.Enabled {
		if err = s.validateRelay(p.tenantID, RelayNodeInput{Name: result.Name, Region: result.Region, Endpoint: result.Endpoint, SecretRef: result.SecretRef}); err != nil {
			return RelayNode{}, err
		}
	}
	result, err = scanRelay(tx.QueryRow(ctx, `UPDATE relay_nodes SET name=$3,region=$4,endpoint=$5,secret_ref=$6,enabled=$7,revision=revision+1 WHERE tenant_id=$1 AND id=$2 RETURNING `+relayColumns, p.tenantID, id, result.Name, result.Region, result.Endpoint, result.SecretRef, result.Enabled))
	if err != nil {
		return RelayNode{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	if err = s.finishRelay(ctx, tx, p, operation, result, keyHash, requestHash, 200); err != nil {
		return RelayNode{}, err
	}
	return result, nil
}
func (s *Service) GetRelayNode(ctx context.Context, p Principal, id string) (RelayNode, error) {
	if !uuidPattern.MatchString(id) {
		return RelayNode{}, fail("INVALID_INPUT", 422)
	}
	tx, err := s.begin(ctx, p, false)
	if err != nil {
		return RelayNode{}, err
	}
	defer rollback(tx)
	result, err := scanRelay(tx.QueryRow(ctx, "SELECT "+relayColumns+" FROM relay_nodes WHERE tenant_id=$1 AND id=$2", p.tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return RelayNode{}, fail("RELAY_NODE_NOT_FOUND", 404)
	}
	if err != nil {
		return RelayNode{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	return result, nil
}
func (s *Service) ListRelayNodes(ctx context.Context, p Principal, page Page) (RelayNodePage, error) {
	limit, cursor, err := parsePage(p, page, "relay_nodes")
	if err != nil {
		return RelayNodePage{}, err
	}
	tx, err := s.begin(ctx, p, false)
	if err != nil {
		return RelayNodePage{}, err
	}
	defer rollback(tx)
	query := "SELECT " + relayColumns + " FROM relay_nodes WHERE tenant_id=$1"
	args := []any{p.tenantID}
	if cursor != nil {
		query += " AND (created_at,id)<($2,$3) ORDER BY created_at DESC,id DESC LIMIT $4"
		args = append(args, cursor.CreatedAt, cursor.ID, limit+1)
	} else {
		query += " ORDER BY created_at DESC,id DESC LIMIT $2"
		args = append(args, limit+1)
	}
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return RelayNodePage{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	defer rows.Close()
	result := RelayNodePage{Items: make([]RelayNode, 0, limit)}
	for rows.Next() {
		value, err := scanRelay(rows)
		if err != nil {
			return RelayNodePage{}, fail("DATABASE_UNAVAILABLE", 503)
		}
		if len(result.Items) == limit {
			last := result.Items[len(result.Items)-1]
			result.NextCursor = encodeCursor(p, "relay_nodes", last.CreatedAt, last.ID)
			break
		}
		result.Items = append(result.Items, value)
	}
	if rows.Err() != nil {
		return RelayNodePage{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	return result, nil
}
