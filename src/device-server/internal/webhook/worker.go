package webhook

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"math/rand/v2"
	"time"
)

type DeliverySender interface {
	Send(context.Context, string, string, string, string, []byte) (int, error)
}
type Worker struct {
	pool   *pgxpool.Pool
	sender DeliverySender
}

func NewWorker(pool *pgxpool.Pool, sender DeliverySender) (*Worker, error) {
	if pool == nil || sender == nil {
		return nil, errors.New("webhook worker requires database and sender")
	}
	return &Worker{pool: pool, sender: sender}, nil
}
func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

// DeliverOne owns the row until its bounded network attempt finishes. A crash
// after receiver success but before commit may redeliver the SAME delivery ID.
// Receivers must durably deduplicate IDs; exactly-once consumption is not promised.
func (w *Worker) DeliverOne(ctx context.Context) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return false, errors.New("webhook database unavailable")
	}
	defer rollback(tx)
	var id, tenant, endpoint string
	var revision int64
	var attempts int
	var body []byte
	err = tx.QueryRow(ctx, `SELECT id::text,tenant_id::text,endpoint_id::text,endpoint_revision,attempts,payload::text FROM webhook_deliveries WHERE state='pending' AND next_attempt_at<=clock_timestamp() ORDER BY next_attempt_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`).Scan(&id, &tenant, &endpoint, &revision, &attempts, &body)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("webhook claim unavailable")
	}
	var target, ref string
	var current int64
	var enabled bool
	// Share lock serializes endpoint configuration changes against this attempt;
	// it does not pretend to retract a request already consumed by a remote server.
	err = tx.QueryRow(ctx, `SELECT e.url,e.secret_ref,e.revision,e.enabled AND t.status='active' FROM webhook_endpoints e JOIN tenants t ON t.id=e.tenant_id WHERE e.id=$1 AND e.tenant_id=$2 FOR SHARE OF e,t`, endpoint, tenant).Scan(&target, &ref, &current, &enabled)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (!enabled || current != revision) {
		_, err = tx.Exec(ctx, `UPDATE webhook_deliveries SET state='cancelled',finished_at=clock_timestamp() WHERE id=$1`, id)
		if err != nil || tx.Commit(ctx) != nil {
			return true, errors.New("webhook cancellation commit unknown")
		}
		return true, nil
	}
	if err != nil {
		return true, errors.New("webhook endpoint unavailable")
	}
	status, sendErr := w.sender.Send(ctx, tenant, ref, target, id, body)
	attempts++
	state := "pending"
	if sendErr == nil && status >= 200 && status < 300 {
		state = "delivered"
	} else if attempts >= 8 || status >= 300 && status < 500 && status != 408 && status != 429 {
		state = "failed"
	}
	delay := (1<<uint(attempts))*5 + rand.IntN(6)
	var statusValue any
	if status >= 100 && status <= 599 {
		statusValue = status
	}
	_, err = tx.Exec(ctx, `UPDATE webhook_deliveries SET state=$2,attempts=$3,last_status=$4,next_attempt_at=clock_timestamp()+($5::integer*interval '1 second'),finished_at=CASE WHEN $2='pending' THEN NULL ELSE clock_timestamp() END WHERE id=$1`, id, state, attempts, statusValue, delay)
	if err != nil || tx.Commit(ctx) != nil {
		return true, errors.New("webhook delivery commit unknown")
	}
	return true, nil
}
func (w *Worker) Run(ctx context.Context) {
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			for i := 0; i < 4; i++ {
				found, err := w.DeliverOne(ctx)
				if err != nil || !found {
					break
				}
			}
		}
	}
}
func (w *Worker) Purge(ctx context.Context) error {
	_, err := w.pool.Exec(ctx, `DELETE FROM webhook_deliveries WHERE id IN (SELECT id FROM webhook_deliveries WHERE finished_at<clock_timestamp()-interval '7 days' AND state<>'pending' ORDER BY finished_at LIMIT 256)`)
	if err != nil {
		return errors.New("webhook cleanup unavailable")
	}
	return nil
}

func (Worker) String() string   { return "[REDACTED webhook worker]" }
func (Worker) GoString() string { return "[REDACTED webhook worker]" }
