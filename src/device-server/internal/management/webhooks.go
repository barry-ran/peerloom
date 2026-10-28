package management

import (
	"context"
	"errors"
	"github.com/barry-ran/peerloom/src/device-server/internal/webhook"
	"github.com/jackc/pgx/v5"
	"strings"
	"time"
)

type WebhookEndpoint struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	URL       string    `json:"url"`
	SecretRef string    `json:"secret_ref"`
	Enabled   bool      `json:"enabled"`
	Revision  int64     `json:"revision"`
	CreatedAt time.Time `json:"created_at"`
}
type WebhookInput struct {
	URL       string `json:"url"`
	SecretRef string `json:"secret_ref"`
}
type WebhookUpdate struct {
	Enabled   *bool   `json:"enabled"`
	URL       *string `json:"url"`
	SecretRef *string `json:"secret_ref"`
}
type WebhookPage struct {
	Items      []WebhookEndpoint `json:"items"`
	NextCursor string            `json:"next_cursor,omitempty"`
}

func (s *Service) WithWebhooks(registry *webhook.Registry) (*Service, error) {
	if registry == nil {
		return nil, errors.New("webhook registry required")
	}
	copy := *s
	copy.webhookRegistry = registry
	return &copy, nil
}

const webhookColumns = "id::text,tenant_id::text,url,secret_ref,enabled,revision,created_at"

func scanWebhook(row scanner) (WebhookEndpoint, error) {
	var value WebhookEndpoint
	err := row.Scan(&value.ID, &value.TenantID, &value.URL, &value.SecretRef, &value.Enabled, &value.Revision, &value.CreatedAt)
	return value, err
}
func (s *Service) CreateWebhook(ctx context.Context, p Principal, input WebhookInput, key string) (WebhookEndpoint, error) {
	if s.webhookRegistry == nil || !s.webhookRegistry.Approved(p.tenantID, input.SecretRef, input.URL) {
		return WebhookEndpoint{}, fail("WEBHOOK_BINDING_NOT_APPROVED", 422)
	}
	tx, err := s.begin(ctx, p, true)
	if err != nil {
		return WebhookEndpoint{}, err
	}
	defer rollback(tx)
	var result WebhookEndpoint
	found, kh, rh, err := s.prepareReplay(ctx, tx, p, "webhook.create", key, input, &result)
	if err != nil || found {
		return result, err
	}
	var count int
	if tx.QueryRow(ctx, `SELECT count(*) FROM webhook_endpoints WHERE tenant_id=$1`, p.tenantID).Scan(&count) != nil {
		return result, fail("DATABASE_UNAVAILABLE", 503)
	}
	if count >= 4 {
		return result, fail("WEBHOOK_ENDPOINT_LIMIT", 429)
	}
	result, err = scanWebhook(tx.QueryRow(ctx, `INSERT INTO webhook_endpoints(tenant_id,url,secret_ref) VALUES($1,$2,$3) RETURNING `+webhookColumns, p.tenantID, input.URL, input.SecretRef))
	if err != nil {
		return result, fail("DATABASE_UNAVAILABLE", 503)
	}
	if err = s.finishWebhook(ctx, tx, p, "webhook.create", result, 201, kh, rh); err != nil {
		return WebhookEndpoint{}, err
	}
	return result, commit(ctx, tx)
}
func (s *Service) UpdateWebhook(ctx context.Context, p Principal, id string, input WebhookUpdate, key string) (WebhookEndpoint, error) {
	if !uuidPattern.MatchString(id) || (input.Enabled == nil && input.URL == nil && input.SecretRef == nil) {
		return WebhookEndpoint{}, fail("INVALID_WEBHOOK_UPDATE", 422)
	}
	tx, err := s.begin(ctx, p, true)
	if err != nil {
		return WebhookEndpoint{}, err
	}
	defer rollback(tx)
	operation := "webhook.update:" + strings.ToLower(id)
	var result WebhookEndpoint
	found, kh, rh, err := s.prepareReplay(ctx, tx, p, operation, key, input, &result)
	if err != nil || found {
		return result, err
	}
	result, err = scanWebhook(tx.QueryRow(ctx, `SELECT `+webhookColumns+` FROM webhook_endpoints WHERE id=$1 AND tenant_id=$2 FOR UPDATE`, id, p.tenantID))
	if errors.Is(err, pgx.ErrNoRows) {
		return result, fail("WEBHOOK_NOT_FOUND", 404)
	}
	if err != nil {
		return result, fail("DATABASE_UNAVAILABLE", 503)
	}
	if input.URL != nil {
		result.URL = *input.URL
	}
	if input.SecretRef != nil {
		result.SecretRef = *input.SecretRef
	}
	if input.Enabled != nil {
		result.Enabled = *input.Enabled
	}
	if (result.Enabled || input.URL != nil || input.SecretRef != nil) && (s.webhookRegistry == nil || !s.webhookRegistry.Approved(p.tenantID, result.SecretRef, result.URL)) {
		return result, fail("WEBHOOK_BINDING_NOT_APPROVED", 422)
	}
	result, err = scanWebhook(tx.QueryRow(ctx, `UPDATE webhook_endpoints SET enabled=$3,url=$4,secret_ref=$5,revision=revision+1 WHERE id=$1 AND tenant_id=$2 RETURNING `+webhookColumns, id, p.tenantID, result.Enabled, result.URL, result.SecretRef))
	if err != nil {
		return result, fail("DATABASE_UNAVAILABLE", 503)
	}
	if err = s.finishWebhook(ctx, tx, p, operation, result, 200, kh, rh); err != nil {
		return WebhookEndpoint{}, err
	}
	return result, commit(ctx, tx)
}
func (s *Service) finishWebhook(ctx context.Context, tx pgx.Tx, p Principal, operation string, result WebhookEndpoint, status int, kh, rh []byte) error {
	if err := recordAudit(ctx, tx, p.tenantID, p.actorType(), p.credentialID, operation, "webhook_endpoint", result.ID, map[string]any{"revision": result.Revision}); err != nil {
		return err
	}
	return s.saveReplay(ctx, tx, p, operation, result.ID, status, kh, rh, result, nil)
}
func (s *Service) ListWebhooks(ctx context.Context, p Principal) (WebhookPage, error) {
	tx, err := s.begin(ctx, p, false)
	if err != nil {
		return WebhookPage{}, err
	}
	defer rollback(tx)
	rows, err := tx.Query(ctx, `SELECT `+webhookColumns+` FROM webhook_endpoints WHERE tenant_id=$1 ORDER BY created_at,id LIMIT 5`, p.tenantID)
	if err != nil {
		return WebhookPage{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	defer rows.Close()
	result := WebhookPage{Items: []WebhookEndpoint{}}
	for rows.Next() {
		value, err := scanWebhook(rows)
		if err != nil {
			return result, fail("DATABASE_UNAVAILABLE", 503)
		}
		result.Items = append(result.Items, value)
	}
	if rows.Err() != nil {
		return result, fail("DATABASE_UNAVAILABLE", 503)
	}
	return result, nil
}
