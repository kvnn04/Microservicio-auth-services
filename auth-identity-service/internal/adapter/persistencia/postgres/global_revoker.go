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

// Motivo del corte global expuesto en eventos (contracts §2).
// SES-04 reutilizará este efecto con audit "reuse_detected".
const globalRevokeReason = "user_request"

// GlobalRevoker implementa auth.GlobalSessionRevoker (CU-SES-02 T-08).
// Tx única PG (verdad): bump valid_after + families revoked + sessions
// DELETE + outbox revoked_all + audit + email, en 1 SELECT+1 UPDATE+1
// DELETE-RETURNING+1 batch CTE de escritura y UN solo COMMIT.
// Redis post-commit (best-effort): sweep by_user + PUBLISH inmediato.
// Redis down → PG verdad + onFallback("redis-down") + igual 200.
// PG down → auth.ErrSessionInfra (el handler NO envía Clear-Cookie).
type GlobalRevoker struct {
	pool       *pgxpool.Pool
	sweep      *redisadapter.GlobalSweep
	onFallback func(reason string)
}

func NewGlobalRevoker(pool *pgxpool.Pool, sweep *redisadapter.GlobalSweep, onFallback func(string)) *GlobalRevoker {
	if onFallback == nil {
		onFallback = func(string) {}
	}
	return &GlobalRevoker{pool: pool, sweep: sweep, onFallback: onFallback}
}

// RevokeAll corta TODO del usuario (incluida la llamante) y siempre bumpea
// valid_after (repeat con 0/0 incluido — harmless y mismo shape 200).
func (s *GlobalRevoker) RevokeAll(ctx context.Context, userID, ip string) (auth.GlobalRevokeResult, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return auth.GlobalRevokeResult{}, auth.ErrGlobalUserNotFound
	}
	if s.pool == nil {
		return auth.GlobalRevokeResult{}, fmt.Errorf("no pool: %w", auth.ErrSessionInfra)
	}
	now := time.Now().UTC()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return auth.GlobalRevokeResult{}, fmt.Errorf("begin %v: %w", err, auth.ErrSessionInfra)
	}
	defer tx.Rollback(ctx)

	// 1. Bump del punto de corte (clock_timestamp: hora real de ejecución).
	// 0 filas → usuario borrado: 401 base, nada que cortar.
	var validAfter time.Time
	var emailNorm string
	if err := tx.QueryRow(ctx, `UPDATE users SET tokens_valid_after = clock_timestamp()
		WHERE id=$1 RETURNING tokens_valid_after, email_normalized`,
		uid).Scan(&validAfter, &emailNorm); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return auth.GlobalRevokeResult{}, auth.ErrGlobalUserNotFound
		}
		return auth.GlobalRevokeResult{}, fmt.Errorf("bump valid_after %v: %w", err, auth.ErrSessionInfra)
	}

	// 2. Families revocadas (cuenta N). Solo las aún vivas: la revocación
	// es monótona (FALSE→TRUE) y el repeat queda en 0/0 idempotente.
	famRes, err := tx.Exec(ctx, `UPDATE refresh_families SET revoked=TRUE WHERE user_id=$1 AND revoked=FALSE`, uid)
	if err != nil {
		return auth.GlobalRevokeResult{}, fmt.Errorf("revoke families %v: %w", err, auth.ErrSessionInfra)
	}
	families := int(famRes.RowsAffected())

	// 3. Sesiones borradas (cuenta M + listas para el sweep Redis).
	type sessRef struct{ sid, fam, jti string }
	var refs []sessRef
	rows, err := tx.Query(ctx, `DELETE FROM sessions WHERE user_id=$1
		RETURNING sid::text, family::text, jti_actual::text`, uid)
	if err != nil {
		return auth.GlobalRevokeResult{}, fmt.Errorf("delete sessions %v: %w", err, auth.ErrSessionInfra)
	}
	for rows.Next() {
		var r sessRef
		if serr := rows.Scan(&r.sid, &r.fam, &r.jti); serr == nil {
			refs = append(refs, r)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return auth.GlobalRevokeResult{}, fmt.Errorf("scan deleted %v: %w", err, auth.ErrSessionInfra)
	}

	// 4. Batch CTE de escritura (1 RTT): outbox revoked_all + audit + email.
	outID := uuid.New()
	auditID := uuid.New()
	mailID := uuid.New()
	revokedPayload := buildRevokedAllPayload(outID, uid, len(refs), families, validAfter, now)
	auditPayload := buildGlobalAuditPayload(auditID, uid, len(refs), families, validAfter)
	mailSubject, mailBody := buildGlobalMail(emailNorm, len(refs), validAfter, ip)
	if _, err := tx.Exec(ctx, `
WITH o1 AS (
  INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
  VALUES ($1,'session.revoked_all',$2,'auth.session.revoked_all.v1',$3,'pending')
  ON CONFLICT (event_id) DO NOTHING RETURNING event_id
),
o2 AS (
  INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
  VALUES ($4,'audit.session.logout_global',$2,'auth.audit.v1',$5,'pending')
  ON CONFLICT (event_id) DO NOTHING RETURNING event_id
)
INSERT INTO email_queue (id, to_email, subject, body_text, status)
VALUES ($6,$7,$8,$9,'pending') ON CONFLICT (id) DO NOTHING`,
		outID, uid, string(revokedPayload),
		auditID, string(auditPayload),
		mailID, emailNorm, mailSubject, mailBody,
	); err != nil {
		return auth.GlobalRevokeResult{}, fmt.Errorf("outbox batch %v: %w", err, auth.ErrSessionInfra)
	}
	if err := tx.Commit(ctx); err != nil {
		return auth.GlobalRevokeResult{}, fmt.Errorf("commit %v: %w", err, auth.ErrSessionInfra)
	}

	// 5. Redis post-commit (best-effort): sweep + PUBLISH inmediato.
	if s.sweep != nil {
		sids := make([]string, 0, len(refs))
		fams := make([]string, 0, len(refs))
		jtis := make([]string, 0, len(refs))
		for _, r := range refs {
			sids = append(sids, r.sid)
			fams = append(fams, r.fam)
			jtis = append(jtis, r.jti)
		}
		if serr := s.sweep.Sweep(ctx, uid.String(), sids, fams, jtis); serr != nil {
			s.onFallback("redis-down")
		} else if perr := s.sweep.PublishRevoked(ctx, string(revokedPayload)); perr != nil {
			s.onFallback("redis-pub-down")
		}
	}

	return auth.GlobalRevokeResult{Sessions: len(refs), Families: families, ValidAfter: validAfter}, nil
}

// buildRevokedAllPayload sobre anidado (igual que logged_out) + reason.
// Se reusa el mismo bytes para outbox durable y PUBLISH inmediato.
func buildRevokedAllPayload(eventID, uid uuid.UUID, sessions, families int, validAfter, now time.Time) []byte {
	b, _ := json.Marshal(map[string]any{
		"event_id": eventID.String(), "event_type": "session.revoked_all",
		"occurred_at": now.Format("2006-01-02T15:04:05Z"),
		"payload": map[string]any{
			"user_id": uid.String(), "sessions": sessions, "families": families,
			"valid_after": validAfter.Format("2006-01-02T15:04:05Z"), "reason": globalRevokeReason,
		},
	})
	return b
}

// buildGlobalAuditPayload fila auth.audit.v1 (action session.logout_global).
func buildGlobalAuditPayload(_ uuid.UUID, uid uuid.UUID, sessions, families int, validAfter time.Time) []byte {
	b, _ := json.Marshal(map[string]any{
		"action": "session.logout_global", "user_id": uid.String(),
		"sessions": sessions, "families": families,
		"valid_after": validAfter.Format("2006-01-02T15:04:05Z"), "result": "ok",
	})
	return b
}

// buildGlobalMail alerta al dueño (N + hora + IP + consejo; sin links
// sensibles salvo login/forgot genéricos — el front los conoce).
func buildGlobalMail(to string, sessions int, validAfter time.Time, ip string) (subject, body string) {
	subject = "Cerraste todas tus sesiones"
	if ip == "" {
		ip = "desconocida"
	}
	body = "Hola,\n\nCerraste todas tus sesiones (" + itoaGlobal(sessions) + " dispositivo(s)) el " +
		validAfter.UTC().Format("2006-01-02 15:04 UTC") +
		" desde la IP aproximada " + ip + ".\n\n" +
		"Si no fuiste tú, cambia tu contraseña cuanto antes desde /login o /forgot.\n"
	_ = to
	return subject, body
}

func itoaGlobal(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

var _ auth.GlobalSessionRevoker = (*GlobalRevoker)(nil)
