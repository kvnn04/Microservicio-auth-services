package kafka

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditLogger implementa shared.AuditLogger vía outbox (tópico auth.audit.v1).
type AuditLogger struct {
	pool *pgxpool.Pool
}

func NewAuditLogger(pool *pgxpool.Pool) *AuditLogger { return &AuditLogger{pool: pool} }

func (a *AuditLogger) Log(ctx context.Context, action string, fields map[string]string) error {
	if a.pool == nil {
		return nil
	}
	eid := uuid.NewString()
	agg := fields["user_id"]
	if agg == "" {
		agg = fields["email_hash"]
	}
	payload := `{"action":"` + action + `"`
	for k, v := range fields {
		payload += `,"` + k + `":"` + v + `"`
	}
	payload += `}`
	var aggID any = agg
	if _, err := uuid.Parse(agg); err != nil {
		aggID = uuid.Nil
	}
	_, err := a.pool.Exec(ctx, `INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
		VALUES ($1::uuid, $2, $3, 'auth.audit.v1', $4::jsonb, 'pending')
		ON CONFLICT (event_id) DO NOTHING`, eid, "audit."+action, aggID, payload)
	return err
}
