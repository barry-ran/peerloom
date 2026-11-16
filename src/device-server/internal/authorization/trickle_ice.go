package authorization

import (
	"context"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/identity"
	"github.com/jackc/pgx/v5"
)

const MaxICECandidates = 256
const MaxICEBytes = 262144

// AuthorizeICEGeneration shares the session lock and revocation/lease checks
// with description admission and recovery. Counters survive socket replacement.
// Candidate contents remain transient; no network addresses are persisted.
func (s *Service) AuthorizeICEGeneration(ctx context.Context, actor identity.Device, id string, generation int64, count, bytes int, complete bool) (Session, bool, error) {
	if count < 0 || count > 16 || bytes < 0 || bytes > 16384 || (count == 0 && !complete) {
		return Session{}, false, failure("INVALID_INPUT", 422)
	}
	deliver := false
	result, err := s.operate(ctx, actor, id, false, func(ctx context.Context, tx pgx.Tx, value Session, _ grant, _ time.Time) (Session, error) {
		if err := accepted(value); err != nil {
			return Session{}, err
		}
		if generation != value.NegotiationGeneration {
			return Session{}, failure("NEGOTIATION_STALE", 409)
		}
		prefix := "source"
		seen := value.SourceOfferSeen
		if actor.ID == value.TargetDeviceID {
			prefix = "target"
			seen = value.TargetAnswerSeen
		}
		if !seen {
			return Session{}, failure("DESCRIPTION_REQUIRED", 409)
		}
		var oldCount, oldBytes int
		var ended bool
		err := tx.QueryRow(ctx, "SELECT "+prefix+"_ice_count,"+prefix+"_ice_bytes,"+prefix+"_ice_complete FROM sessions WHERE tenant_id=$1 AND id=$2", value.TenantID, value.ID).Scan(&oldCount, &oldBytes, &ended)
		if err != nil {
			return Session{}, databaseError(err)
		}
		if oldCount+count > MaxICECandidates || oldBytes+bytes > MaxICEBytes {
			return Session{}, failure("ICE_LIMIT", 429)
		}
		_, err = tx.Exec(ctx, "UPDATE sessions SET "+prefix+"_ice_count=$3,"+prefix+"_ice_bytes=$4,"+prefix+"_ice_complete=$5 WHERE tenant_id=$1 AND id=$2", value.TenantID, value.ID, oldCount+count, oldBytes+bytes, ended || complete)
		if err != nil {
			return Session{}, databaseError(err)
		}
		deliver = !ended
		return value, nil
	})
	return result, deliver && err == nil, err
}
