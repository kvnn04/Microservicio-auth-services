package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	redisadapter "auth-identity-service/internal/adapter/persistencia/redis"
	"auth-identity-service/internal/domain/auth"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SessionLister implementa auth.SessionLister + auth.SessionToucher
// (CU-SES-03 T-08). PG es la verdad ordenada; Redis es fast-path
// all-or-nothing (si falta un miembro → PG, nunca lista parcial).
// RevokeOne: triple-capa del objetivo + outbox revoked_one + audit + email,
// todo en UN batch CTE y UN commit (patrón SES-01/02).
type SessionLister struct {
	pool       *pgxpool.Pool
	cache      *redisadapter.SessionListCache
	onFallback func(reason string)
}

func NewSessionLister(pool *pgxpool.Pool, cache *redisadapter.SessionListCache, onFallback func(string)) *SessionLister {
	if onFallback == nil {
		onFallback = func(string) {}
	}
	return &SessionLister{pool: pool, cache: cache, onFallback: onFallback}
}

// List devuelve las vivas del usuario (last_seen DESC). Intenta Redis
// (SMEMBERS+MGET completos); cualquier miss → PG. PG down → ErrSessionInfra
// (el servicio responde 500, jamás 200 []).
// El fast-path exige PG vivo (probe SELECT 1 barato): con PG caído la lista
// cacheada podría estar rancia y el spec ordena 500 antes que datos
// posiblemente viejos. Redis caído → PG directo + WARN.
func (s *SessionLister) List(ctx context.Context, userID string) ([]auth.SessionView, error) {
	if _, err := uuid.Parse(userID); err != nil {
		return nil, fmt.Errorf("bad user: %w", auth.ErrSessionInfra)
	}
	if s.pool == nil {
		return nil, fmt.Errorf("no pool: %w", auth.ErrSessionInfra)
	}
	// Gate PG (1 RTT barato): sin verdad no hay fast-path.
	if err := s.pool.QueryRow(ctx, `SELECT 1`).Scan(new(int)); err != nil {
		return nil, fmt.Errorf("pg probe %v: %w", err, auth.ErrSessionInfra)
	}
	if views, ok := s.listFromCache(ctx, userID); ok {
		return views, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT sid::text, device_label, ip_masked,
		location, created_at, last_seen
		FROM sessions WHERE user_id=$1::uuid ORDER BY last_seen DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("select sessions %v: %w", err, auth.ErrSessionInfra)
	}
	defer rows.Close()
	var out []auth.SessionView
	for rows.Next() {
		var v auth.SessionView
		var loc *string
		if serr := rows.Scan(&v.SID, &v.DeviceLabel, &v.IPMasked, &loc, &v.CreatedAt, &v.LastSeen); serr != nil {
			return nil, fmt.Errorf("scan %v: %w", serr, auth.ErrSessionInfra)
		}
		if loc != nil {
			v.Location = *loc
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows %v: %w", err, auth.ErrSessionInfra)
	}
	if out == nil {
		out = []auth.SessionView{}
	}
	return out, nil
}

// listFromCache all-or-nothing: SMEMBERS → MGET sess:* → parse TODOS.
// ok=false ante cualquier miss/parcial (→ PG, verdad). Error Redis → WARN.
func (s *SessionLister) listFromCache(ctx context.Context, userID string) ([]auth.SessionView, bool) {
	if s.cache == nil {
		return nil, false
	}
	views, err := s.cache.List(ctx, userID)
	if err != nil {
		// Miss normal (índice vacío/parcial) → PG sin ruido.
		if !redisadapter.IsMiss(err) {
			s.onFallback("redis-down")
		}
		return nil, false
	}
	if views == nil {
		return nil, false
	}
	return views, true
}

// RevokeOne mata la sesión objetivo (debe ser de userID y ≠ current;
// el servicio ya validó formato y actual). Miss → ErrSessionNotFound
// (ajena/inexistente/muerta, idéntico por supuesto Q4).
func (s *SessionLister) RevokeOne(ctx context.Context, userID, currentSID, targetSID string) (auth.RevokedOne, error) {
	target, err := uuid.Parse(targetSID)
	if err != nil {
		return auth.RevokedOne{}, auth.ErrSessionNotFound
	}
	uid, err := uuid.Parse(userID)
	if err != nil {
		return auth.RevokedOne{}, auth.ErrSessionNotFound
	}
	if s.pool == nil {
		return auth.RevokedOne{}, fmt.Errorf("no pool: %w", auth.ErrSessionInfra)
	}
	now := time.Now().UTC()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return auth.RevokedOne{}, fmt.Errorf("begin %v: %w", err, auth.ErrSessionInfra)
	}
	defer tx.Rollback(ctx)

	// SELECT con lock (miss → NotFound; la jti_actual se denylistea).
	var family, jti uuid.UUID
	var label, masked string
	var loc *string
	serr := tx.QueryRow(ctx, `SELECT family, jti_actual, device_label, ip_masked, location
		FROM sessions WHERE sid=$1 AND user_id=$2 FOR UPDATE`, target, uid).Scan(
		&family, &jti, &label, &masked, &loc)
	if serr != nil {
		if errors.Is(serr, pgx.ErrNoRows) {
			return auth.RevokedOne{}, auth.ErrSessionNotFound
		}
		return auth.RevokedOne{}, fmt.Errorf("select target %v: %w", serr, auth.ErrSessionInfra)
	}
	location := ""
	if loc != nil {
		location = *loc
	}

	// Batch CTE (1 RTT): family revoked + DELETE target + denylist jti
	// (EX=AccessTTL máx: el exp exacto del Access objetivo no vive en PG) +
	// outbox revoked_one + audit + email al dueño.
	outID := uuid.New()
	auditID := uuid.New()
	mailID := uuid.New()
	revokedPayload := buildRevokedOnePayload(outID, uid, target, label, now)
	auditPayload := buildRevokeOneAuditPayload(uid, target, "ok")
	mailSubject := "Cerraste una sesión a distancia"
	where := ""
	if location != "" {
		where = ", " + location
	}
	mailBody := "Hola,\n\nCerraste la sesión de " + orUnknown(label) + " (" + orUnknown(masked) + where + ") el " +
		now.UTC().Format("2006-01-02 15:04 UTC") +
		".\n\nSi no fuiste tú, cambia tu contraseña cuanto antes.\n"
	var email string
	_ = tx.QueryRow(ctx, `SELECT email_normalized FROM users WHERE id=$1`, uid).Scan(&email)
	if _, err := tx.Exec(ctx, `
WITH u AS (
  UPDATE refresh_families SET revoked=TRUE WHERE family=$1 RETURNING family
),
j AS (
  INSERT INTO revoked_jtis (jti, user_id, expires_at)
  VALUES ($2,$3,$4) ON CONFLICT (jti) DO NOTHING RETURNING jti
),
d AS (
  DELETE FROM sessions WHERE sid=$5 RETURNING sid
),
o1 AS (
  INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
  VALUES ($6,'session.revoked_one',$3,'auth.session.revoked_one.v1',$7,'pending')
  ON CONFLICT (event_id) DO NOTHING RETURNING event_id
),
o2 AS (
  INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
  VALUES ($8,'audit.session.revoke_one',$3,'auth.audit.v1',$9,'pending')
  ON CONFLICT (event_id) DO NOTHING RETURNING event_id
)
INSERT INTO email_queue (id, to_email, subject, body_text, status)
VALUES ($10,$11,$12,$13,'pending') ON CONFLICT (id) DO NOTHING`,
		family, jti, uid, now.Add(auth.AccessTTL),
		target, outID, string(revokedPayload),
		auditID, string(auditPayload),
		mailID, email, mailSubject, mailBody,
	); err != nil {
		return auth.RevokedOne{}, fmt.Errorf("revoke batch %v: %w", err, auth.ErrSessionInfra)
	}
	if err := tx.Commit(ctx); err != nil {
		return auth.RevokedOne{}, fmt.Errorf("commit %v: %w", err, auth.ErrSessionInfra)
	}

	// Redis post-commit (best-effort): DEL objetivo + denylist jti.
	// currentSID ya lo filtró el servicio (nunca llega aquí); el WHERE por
	// user_id+sid lo haría imposible de todos modos (defensa en profundidad).
	if s.cache != nil {
		if rerr := s.cache.RevokeTarget(ctx, target.String(), family.String(), jti.String(), uid.String()); rerr != nil {
			s.onFallback("redis-down")
		}
	}
	_ = currentSID // validado por el servicio; el WHERE user_id+sid lo re-asegura.
	return auth.RevokedOne{SID: target.String(), DeviceLabel: label, IPMasked: masked}, nil
}

// Touch refresca last_seen con debounce (supuesto Q5 confirmado).
// Flujo: SETNX touch:<sid> EX 5min (si existe → nil, debounced) → UPDATE PG
// + espejo Redis (GET-modify-SET). Todo best-effort: cualquier error → nil.
func (s *SessionLister) Touch(ctx context.Context, userID, sid string, now time.Time) error {
	if _, err := uuid.Parse(sid); err != nil {
		return nil
	}
	if s.cache != nil {
		acquired, derr := s.cache.AcquireTouch(ctx, sid, auth.TouchDebounce)
		if derr != nil || !acquired {
			return nil // debounced o Redis caído (PG lo dirá todo)
		}
	}
	if s.pool == nil {
		return nil
	}
	_, _ = s.pool.Exec(ctx, `UPDATE sessions SET last_seen=$3
		WHERE sid=$1::uuid AND user_id=$2::uuid`, sid, userID, now.UTC())
	if s.cache != nil {
		_ = s.cache.MirrorLastSeen(ctx, sid, now.UTC())
	}
	return nil
}

// buildRevokedOnePayload sobre anidado (igual familia revoked_one) con
// device_label para el email/worker (sin tokens/jti/family).
func buildRevokedOnePayload(eventID, uid, sid uuid.UUID, label string, now time.Time) []byte {
	b, _ := json.Marshal(map[string]any{
		"event_id": eventID.String(), "event_type": "session.revoked_one",
		"occurred_at": now.Format("2006-01-02T15:04:05Z"),
		"payload": map[string]any{
			"user_id": uid.String(), "sid": sid.String(),
			"device_label": orUnknown(label), "by": "self",
		},
	})
	return b
}

// buildRevokeOneAuditPayload fila auth.audit.v1 (action session.revoke_one).
func buildRevokeOneAuditPayload(uid, sid uuid.UUID, result string) []byte {
	b, _ := json.Marshal(map[string]any{
		"action": "session.revoke_one", "user_id": uid.String(),
		"target_sid": sid.String(), "result": result,
	})
	return b
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

var _ auth.SessionLister = (*SessionLister)(nil)
var _ auth.SessionToucher = (*SessionLister)(nil)
