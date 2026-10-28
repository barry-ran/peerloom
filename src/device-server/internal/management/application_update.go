package management

import (
	"context"
	"errors"
	"strings"

	"github.com/barry-ran/peerloom/src/device-server/internal/authorization"
	"github.com/jackc/pgx/v5"
)

type ApplicationUpdate struct {
	Name                  *string `json:"name"`
	RequireTargetApproval *bool   `json:"require_target_approval"`
	MaxConnections        *int    `json:"max_connections"`
	Enabled               *bool   `json:"enabled"`
}

type ApplicationChange struct {
	Application Application             `json:"application"`
	Sessions    []authorization.Session `json:"closed_sessions"`
}

func (s *Service) UpdateApplication(ctx context.Context, p Principal, id string, input ApplicationUpdate, key string) (ApplicationChange, error) {
	if !uuidPattern.MatchString(id) || (input.Name != nil && !validText(*input.Name, 128)) || (input.MaxConnections != nil && (*input.MaxConnections < 0 || *input.MaxConnections > 1024)) {
		return ApplicationChange{}, fail("INVALID_APPLICATION_PROPERTIES", 422)
	}
	if input.Name == nil && input.RequireTargetApproval == nil && input.MaxConnections == nil && input.Enabled == nil {
		return ApplicationChange{}, fail("EMPTY_PATCH", 422)
	}
	id = strings.ToLower(id)
	tx, err := s.begin(ctx, p, true)
	if err != nil {
		return ApplicationChange{}, err
	}
	defer rollback(tx)
	var result ApplicationChange
	request := struct {
		ID         string
		Properties ApplicationUpdate
	}{id, input}
	found, kh, rh, err := s.prepareReplay(ctx, tx, p, "application.update", key, request, &result)
	if err != nil || found {
		return result, err
	}
	result.Application, err = scanApplication(tx.QueryRow(ctx, `UPDATE applications SET name=COALESCE($3,name),require_target_approval=COALESCE($4,require_target_approval),max_connections=COALESCE($5,max_connections),enabled=COALESCE($6,enabled)
WHERE tenant_id=$1 AND id=$2 RETURNING `+applicationColumns, p.tenantID, id, input.Name, input.RequireTargetApproval, input.MaxConnections, input.Enabled))
	if errors.Is(err, pgx.ErrNoRows) {
		return ApplicationChange{}, fail("APPLICATION_NOT_FOUND", 404)
	}
	if err != nil {
		return ApplicationChange{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	result.Sessions = make([]authorization.Session, 0)
	if input.Enabled != nil && !*input.Enabled {
		result.Sessions, err = authorization.CloseForApplicationTx(ctx, tx, p.tenantID, id, "APPLICATION_DISABLED")
		if err != nil {
			return ApplicationChange{}, bridgeError(err)
		}
	}
	if err = s.finishMutation(ctx, tx, p, "application.update", "application", id, kh, rh, result); err != nil {
		return ApplicationChange{}, err
	}
	if err = commit(ctx, tx); err != nil {
		return ApplicationChange{}, err
	}
	return result, nil
}
