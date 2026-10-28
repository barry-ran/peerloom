package adminauth

import (
	"context"
	"errors"
	"github.com/barry-ran/peerloom/src/device-server/internal/management"
	"github.com/jackc/pgx/v5"
)

func (s *Service) AuthenticateBrowser(ctx context.Context, token string) (management.BrowserIdentity, error) {
	session, err := s.Session(ctx, token)
	if err != nil {
		return management.BrowserIdentity{}, err
	}
	return management.BrowserIdentity{TenantID: session.TenantID, UserID: session.UserID, SessionID: session.SessionID}, nil
}
func (s *Service) RevalidateBrowser(ctx context.Context, tx pgx.Tx, identity management.BrowserIdentity) (management.Scope, error) {
	var scope management.Scope
	err := tx.QueryRow(ctx, `SELECT u.scope FROM admin_sessions s JOIN admin_users u ON (u.id,u.tenant_id)=(s.user_id,s.tenant_id) JOIN tenants t ON t.id=s.tenant_id WHERE s.id=$1 AND s.user_id=$2 AND s.tenant_id=$3 AND s.expires_at>clock_timestamp() AND u.enabled AND t.status='active' FOR SHARE OF s,u,t`, identity.SessionID, identity.UserID, identity.TenantID).Scan(&scope)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", problem("ADMIN_AUTH_INVALID", 401)
	}
	if err != nil {
		return "", problem("AUTH_UNAVAILABLE", 503)
	}
	return scope, nil
}
