package management

import (
	"context"
	"errors"
	"strings"

	"github.com/barry-ran/peerloom/src/device-server/internal/authorization"
	"github.com/jackc/pgx/v5"
)

type ApplicationUpdate struct {
	ExclusiveTarget       *bool   `json:"exclusive_target"`
	RegistrationMode      *string `json:"registration_mode"`
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
	if input.RegistrationMode != nil && *input.RegistrationMode != "grant" && *input.RegistrationMode != "direct" {
		return ApplicationChange{}, fail("REGISTRATION_MODE_UNSUPPORTED", 422)
	}
	if !uuidPattern.MatchString(id) || (input.Name != nil && !validText(*input.Name, 128)) || (input.MaxConnections != nil && (*input.MaxConnections < -1 || *input.MaxConnections > 2147483647)) {
		return ApplicationChange{}, fail("INVALID_APPLICATION_PROPERTIES", 422)
	}
	if input.Name == nil && input.RequireTargetApproval == nil && input.MaxConnections == nil && input.Enabled == nil && input.RegistrationMode == nil && input.ExclusiveTarget == nil {
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
	if input.ExclusiveTarget != nil && *input.ExclusiveTarget {
		var unsafe bool
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sessions s JOIN devices d ON d.id=s.target_device_id AND d.tenant_id=s.tenant_id WHERE s.tenant_id=$1 AND d.application_id=$2 AND s.target_epoch=0 AND (s.state<>'closed' OR GREATEST(s.source_lease_expires_at,s.target_lease_expires_at)+interval '2 seconds'>clock_timestamp()))`, p.tenantID, id).Scan(&unsafe)
		if err != nil {
			return result, fail("DATABASE_UNAVAILABLE", 503)
		}
		if unsafe {
			return result, fail("EXCLUSIVE_POLICY_BUSY", 409)
		}
	}
	result.Application, err = scanApplication(tx.QueryRow(ctx, `UPDATE applications SET name=COALESCE($3,name),require_target_approval=COALESCE($4,require_target_approval),max_connections=COALESCE($5,max_connections),enabled=COALESCE($6,enabled),registration_mode=COALESCE($7,registration_mode),exclusive_target=COALESCE($8,exclusive_target)
WHERE tenant_id=$1 AND id=$2 RETURNING `+applicationColumns, p.tenantID, id, input.Name, input.RequireTargetApproval, input.MaxConnections, input.Enabled, input.RegistrationMode, input.ExclusiveTarget))
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
