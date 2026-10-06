package postgres

import (
	"context"
	"errors"
	"fmt"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/user"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SessionStore implementa auth.SessionStore (CU-AUTH-04 T-08).
// Tx atómica: sessions + refresh_families + refresh_hashes + outbox
// (+ LRU-20: al crear la 21ª revoca la más vieja por last_seen).
type SessionStore struct {
	pool *pgxpool.Pool
}

func NewSessionStore(pool *pgxpool.Pool) *SessionStore {
	return &SessionStore{pool: pool}
}

// Create persiste en UNA Tx PG (write-through: Redis lo hace el servicio).
func (s *SessionStore) Create(ctx context.Context, sess auth.Session, fam auth.RefreshFamily, h auth.RefreshHash, evt user.OutboxPayload, _ *user.OutboxPayload) (string, error) {
	sid, err := uuid.Parse(sess.SID)
	if err != nil {
		return "", fmt.Errorf("bad sid: %w", auth.ErrInvalidSessionRequest)
	}
	uid, err := uuid.Parse(sess.UserID)
	if err != nil {
		return "", fmt.Errorf("bad user: %w", auth.ErrInvalidSessionRequest)
	}
	family, err := uuid.Parse(sess.Family)
	if err != nil {
		return "", fmt.Errorf("bad family: %w", auth.ErrInvalidSessionRequest)
	}
	jti, err := uuid.Parse(sess.JTI)
	if err != nil {
		return "", fmt.Errorf("bad jti: %w", auth.ErrInvalidSessionRequest)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("begin %v: %w", err, auth.ErrSessionInfra)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `INSERT INTO sessions
		(sid, user_id, family, jti_actual, device_hash, ip_hash, created_at, last_seen, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		sid, uid, family, jti, sess.DeviceHash, sess.IPHash,
		sess.CreatedAt, sess.LastSeen, sess.ExpiresAt,
	); err != nil {
		if isSessionUniqueViolation(err) {
			return "", auth.ErrSessionConflict
		}
		return "", fmt.Errorf("insert session %v: %w", err, auth.ErrSessionInfra)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO refresh_families
		(family, user_id, current_hash, parent_hash, counter, absolute_exp, revoked)
		VALUES ($1,$2,$3,$4,$5,$6,FALSE)`,
		family, uid, fam.CurrentHash, fam.ParentHash, fam.Counter, fam.AbsoluteExp,
	); err != nil {
		if isSessionUniqueViolation(err) {
			return "", auth.ErrSessionConflict
		}
		return "", fmt.Errorf("insert family %v: %w", err, auth.ErrSessionInfra)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO refresh_hashes
		(hash, family, counter, expires_at) VALUES ($1,$2,$3,$4)`,
		h.Hash, family, h.Counter, h.ExpiresAt,
	); err != nil {
		if isSessionUniqueViolation(err) {
			return "", auth.ErrSessionConflict
		}
		return "", fmt.Errorf("insert hash %v: %w", err, auth.ErrSessionInfra)
	}
	// Outbox session.issued (el relay Kafka lo drena; DLQ auth.dlq.v1).
	eid, err := uuid.Parse(evt.EventID)
	if err != nil {
		return "", fmt.Errorf("bad event id: %w", auth.ErrInvalidSessionRequest)
	}
	agg, err := uuid.Parse(evt.AggregateID)
	if err != nil {
		return "", fmt.Errorf("bad aggregate: %w", auth.ErrInvalidSessionRequest)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO outbox
		(event_id, event_type, aggregate_id, topic, payload, status)
		VALUES ($1,$2,$3,$4,$5,'pending') ON CONFLICT (event_id) DO NOTHING`,
		eid, evt.EventType, agg, evt.Topic, string(evt.PayloadJSON),
	); err != nil {
		return "", fmt.Errorf("insert outbox: %w", auth.ErrSessionInfra)
	}

	// LRU-20: cuenta y evicta la más vieja si excede.
	evicted := ""
	var count int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM sessions WHERE user_id=$1`, uid).Scan(&count); err != nil {
		return "", fmt.Errorf("count sessions: %w", auth.ErrSessionInfra)
	}
	if count > auth.MaxSessionsPerUser {
		var oldSID uuid.UUID
		var oldFam uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT sid, family FROM sessions
			WHERE user_id=$1 ORDER BY last_seen ASC LIMIT 1`, uid).Scan(&oldSID, &oldFam); err == nil {
			// No borra la recién creada (es la más nueva por last_seen=now).
			if oldSID != sid {
				evicted = oldSID.String()
				_, _ = tx.Exec(ctx, `DELETE FROM sessions WHERE sid=$1`, oldSID)
				_, _ = tx.Exec(ctx, `UPDATE refresh_families SET revoked=TRUE WHERE family=$1`, oldFam)
				evID := uuid.New()
				evPayload := `{"evicted_sid":"` + evicted + `","reason":"lru"}`
				_, _ = tx.Exec(ctx, `INSERT INTO outbox
					(event_id, event_type, aggregate_id, topic, payload, status)
					VALUES ($1,'session.evicted',$2,'auth.session.evicted.v1',$3,'pending')`,
					evID, uid, evPayload)
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		if isSessionUniqueViolation(err) {
			return "", auth.ErrSessionConflict
		}
		return "", fmt.Errorf("commit: %w", auth.ErrSessionInfra)
	}
	return evicted, nil
}

func isSessionUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	// pgx no expone código sin pgconn; fallback por mensaje 23505/unique.
	msg := err.Error()
	for _, sub := range []string{"23505", "duplicate key", "already exists", "UNIQUE"} {
		if len(msg) >= len(sub) && sessionContainsFold(msg, sub) {
			return true
		}
	}
	return errors.Is(err, auth.ErrSessionConflict)
}

func sessionContainsFold(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	low := func(b byte) byte {
		if b >= 'A' && b <= 'Z' {
			return b + 32
		}
		return b
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		ok := true
		for j := 0; j < len(sub); j++ {
			if low(s[i+j]) != low(sub[j]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

var _ auth.SessionStore = (*SessionStore)(nil)
