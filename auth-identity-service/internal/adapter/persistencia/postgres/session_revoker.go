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

// SessionRevoker implementa auth.SessionRevoker (CU-SES-01 T-08, optimizado T-13).
// Tx atómica PG (verdad) + write-through Redis (best-effort) + outbox.
// Para cumplir el SLO p95<150ms, la Tx hace UN solo SELECT (JOIN) y UN solo
// batch CTE de escritura (1 RTT: UPDATE family + denylist + DELETE sess +
// outbox logged_out + outbox audit), con UN solo COMMIT. La fila de
// auditoría viaja en la misma Tx (spec §3.4: "INSERT outbox + audit"), con
// idéntico sobre `auth.audit.v1` que el AuditLogger de Kafka, así el relay
// la drena igual y el servicio no hace un segundo INSERT+commit.
// Redis down → PG verdad + onFallback("redis-down") + igual 200.
// PG down → auth.ErrSessionInfra (el handler NO envía Clear-Cookie).
type SessionRevoker struct {
	pool       *pgxpool.Pool
	cache      *redisadapter.LogoutCache
	onFallback func(reason string)
}

func NewSessionRevoker(pool *pgxpool.Pool, cache *redisadapter.LogoutCache, onFallback func(string)) *SessionRevoker {
	if onFallback == nil {
		onFallback = func(string) {}
	}
	return &SessionRevoker{pool: pool, cache: cache, onFallback: onFallback}
}

// revokeBatchCTE escribe el set completo de revocación en UN RTT:
// family→revoked, denylist del jti, borrado de sesión y ambas filas outbox
// (logged_out para el relay de sesiones + audit para trazabilidad).
// Los CTEs data-modifying se ejecutan siempre (1 vez) y comparten snapshot,
// por lo que el lote es atómico dentro de la Tx que lo envuelve.
const revokeBatchCTE = `
WITH u AS (
  UPDATE refresh_families SET revoked=TRUE WHERE family=$1 RETURNING family
),
j AS (
  INSERT INTO revoked_jtis (jti, user_id, expires_at)
  VALUES ($4,$3,$5) ON CONFLICT (jti) DO NOTHING RETURNING jti
),
d AS (
  DELETE FROM sessions WHERE sid=$2 RETURNING sid
),
o1 AS (
  INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
  VALUES ($6,'session.logged_out',$3,'auth.session.logged_out.v1',$7,'pending')
  ON CONFLICT (event_id) DO NOTHING RETURNING event_id
)
INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
VALUES ($8,'audit.session.logout',$3,'auth.audit.v1',$9,'pending')
ON CONFLICT (event_id) DO NOTHING`

// alreadyBatchCTE asegura denylist + deja rastro de auditoría del intento,
// SIN evento logged_out (evita doble-outbox en replays, RN-04).
const alreadyBatchCTE = `
WITH j AS (
  INSERT INTO revoked_jtis (jti, user_id, expires_at)
  VALUES ($1,$2,$3) ON CONFLICT (jti) DO NOTHING RETURNING jti
)
INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
VALUES ($4,'audit.session.logout',$2,'auth.audit.v1',$5,'pending')
ON CONFLICT (event_id) DO NOTHING`

// RevokeSID revoca family+sess+jti del sid del Bearer.
// Miss (0 filas) → Already 200 sin doble-outbox (solo denylist+audit).
func (s *SessionRevoker) RevokeSID(ctx context.Context, id auth.LogoutIdentity) (auth.RevokedSession, error) {
	if err := id.Validate(); err != nil {
		return auth.RevokedSession{}, auth.ErrLogoutNotFound
	}
	sid, err := uuid.Parse(id.SID)
	if err != nil {
		return auth.RevokedSession{}, auth.ErrLogoutNotFound
	}
	uid, err := uuid.Parse(id.UserID)
	if err != nil {
		return auth.RevokedSession{}, auth.ErrLogoutNotFound
	}
	jti, err := uuid.Parse(id.JTI)
	if err != nil {
		return auth.RevokedSession{}, auth.ErrLogoutNotFound
	}
	if s.pool == nil {
		return auth.RevokedSession{}, fmt.Errorf("no pool: %w", auth.ErrSessionInfra)
	}
	now := time.Now().UTC()
	ttl := auth.DenylistTTL(id.ExpiresAt, now)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return auth.RevokedSession{}, fmt.Errorf("begin %v: %w", err, auth.ErrSessionInfra)
	}
	defer tx.Rollback(ctx)

	// Único SELECT: sesión + hash actual (LEFT JOIN tolera family huérfana;
	// en ese borde se limpia igual la sesión y se denylistea el jti).
	var family uuid.UUID
	var dbJTI uuid.UUID
	var currentHash *string
	serr := tx.QueryRow(ctx, `SELECT s.family, s.jti_actual, f.current_hash
		FROM sessions s LEFT JOIN refresh_families f ON f.family = s.family
		WHERE s.sid=$1 AND s.user_id=$2`, sid, uid).Scan(&family, &dbJTI, &currentHash)
	if serr != nil {
		if errors.Is(serr, pgx.ErrNoRows) {
			if cerr := s.alreadyTx(ctx, tx, jti, uid, id.ExpiresAt, id, ""); cerr != nil {
				return auth.RevokedSession{}, cerr
			}
			if err := tx.Commit(ctx); err != nil {
				return auth.RevokedSession{}, fmt.Errorf("commit %v: %w", err, auth.ErrSessionInfra)
			}
			s.redisRevokeBestEffort(ctx, id.SID, "", id.JTI, ttl)
			return auth.RevokedSession{
				Result:   auth.LogoutAlreadyLoggedOut,
				Identity: auth.LogoutIdentity{UserID: id.UserID, SID: id.SID, JTI: id.JTI, ExpiresAt: id.ExpiresAt},
			}, nil
		}
		return auth.RevokedSession{}, fmt.Errorf("select session %v: %w", serr, auth.ErrSessionInfra)
	}

	outID := uuid.New()
	auditID := uuid.New()
	loggedPayload := buildLoggedOutPayload(outID, uid, sid, family, jti, false, now)
	auditPayload := buildAuditPayload(uid, sid.String(), family.String(), jti.String(), "ok")
	if _, err := tx.Exec(ctx, revokeBatchCTE,
		family, sid, uid, jti, id.ExpiresAt, outID, string(loggedPayload), auditID, string(auditPayload),
	); err != nil {
		return auth.RevokedSession{}, fmt.Errorf("revoke batch %v: %w", err, auth.ErrSessionInfra)
	}
	if err := tx.Commit(ctx); err != nil {
		return auth.RevokedSession{}, fmt.Errorf("commit %v: %w", err, auth.ErrSessionInfra)
	}

	// Redis write-through (best-effort; PG es la verdad).
	s.redisRevokeBestEffort(ctx, sid.String(), family.String(), jti.String(), ttl)
	hash := ""
	if currentHash != nil {
		hash = *currentHash
	}
	if hash != "" && s.cache != nil {
		_ = s.cache.RevokeByHash(ctx, sid.String(), family.String(), jti.String(), hash, ttl)
	}

	return auth.RevokedSession{
		Result: auth.LogoutLoggedOut,
		Identity: auth.LogoutIdentity{
			UserID: uid.String(), SID: sid.String(), JTI: jti.String(),
			Family: family.String(), ExpiresAt: id.ExpiresAt,
		},
	}, nil
}

// alreadyTx registra denylist+audit del intento dentro de la Tx abierta
// (1 RTT, sin evento logged_out para no duplicar outbox).
func (s *SessionRevoker) alreadyTx(ctx context.Context, tx pgx.Tx, jti, uid uuid.UUID, exp time.Time, id auth.LogoutIdentity, family string) error {
	auditID := uuid.New()
	auditPayload := buildAuditPayload(uid, id.SID, family, id.JTI, "already")
	if _, err := tx.Exec(ctx, alreadyBatchCTE,
		jti, uid, exp, auditID, string(auditPayload),
	); err != nil {
		return fmt.Errorf("already batch %v: %w", err, auth.ErrSessionInfra)
	}
	return nil
}

// RevokeByRefreshHash localiza family→sid vía hash SHA-256 hex y revoca.
// Hash desconocido → Already 200 (sin oráculo). TTL denylist 15min
// (sin Bearer no conocemos el exp exacto; 15min cubre el peor caso).
func (s *SessionRevoker) RevokeByRefreshHash(ctx context.Context, refreshHash string) (auth.RevokedSession, error) {
	if len(refreshHash) != 64 || !isHex(refreshHash) {
		return auth.RevokedSession{}, auth.ErrLogoutNotFound
	}
	if s.pool == nil {
		return auth.RevokedSession{}, fmt.Errorf("no pool: %w", auth.ErrSessionInfra)
	}
	now := time.Now().UTC()

	// Atajo Redis (índice que Issue mantiene): evita el lookup hash→family
	// en PG. Miss o error → verdad PG (una sola consulta con JOIN).
	familyStr := ""
	if s.cache != nil {
		familyStr = s.cache.LookupFamilyByHash(ctx, refreshHash)
	}
	var family uuid.UUID
	var uid uuid.UUID
	var revoked bool
	var currentHash string
	if familyStr != "" {
		if f, err := uuid.Parse(familyStr); err == nil {
			family = f
			if err := s.pool.QueryRow(ctx, `SELECT user_id, revoked, current_hash
				FROM refresh_families WHERE family=$1`, family).Scan(&uid, &revoked, &currentHash); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return auth.RevokedSession{Result: auth.LogoutAlreadyLoggedOut}, nil
				}
				return auth.RevokedSession{}, fmt.Errorf("lookup family %v: %w", err, auth.ErrSessionInfra)
			}
		}
	}
	if family == uuid.Nil {
		if err := s.pool.QueryRow(ctx, `SELECT f.family, f.user_id, f.revoked, f.current_hash
			FROM refresh_hashes h JOIN refresh_families f ON f.family = h.family
			WHERE h.hash=$1`, refreshHash).Scan(&family, &uid, &revoked, &currentHash); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return auth.RevokedSession{Result: auth.LogoutAlreadyLoggedOut}, nil
			}
			return auth.RevokedSession{}, fmt.Errorf("lookup hash %v: %w", err, auth.ErrSessionInfra)
		}
	}

	type row struct{ sid, jti string }
	var rows []row
	rs, qerr := s.pool.Query(ctx, `SELECT sid::text, jti_actual::text FROM sessions WHERE family=$1`, family)
	if qerr != nil {
		return auth.RevokedSession{}, fmt.Errorf("select sessions %v: %w", qerr, auth.ErrSessionInfra)
	}
	for rs.Next() {
		var r row
		if serr := rs.Scan(&r.sid, &r.jti); serr == nil {
			rows = append(rows, r)
		}
	}
	rs.Close()
	if rs.Err() != nil {
		return auth.RevokedSession{}, fmt.Errorf("scan sessions %v: %w", rs.Err(), auth.ErrSessionInfra)
	}
	if len(rows) == 0 {
		// Sin sesiones: si ya revocada → Already; si no (borde) → revoca family.
		if revoked {
			return auth.RevokedSession{
				Result: auth.LogoutAlreadyLoggedOut,
				Identity: auth.LogoutIdentity{UserID: uid.String(), Family: family.String()},
			}, nil
		}
		exp := now.Add(auth.AccessTTL)
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return auth.RevokedSession{}, fmt.Errorf("begin %v: %w", err, auth.ErrSessionInfra)
		}
		defer tx.Rollback(ctx)
		outID := uuid.New()
		auditID := uuid.New()
		loggedPayload := buildLoggedOutPayload(outID, uid, uuid.Nil, family, uuid.Nil, false, now)
		auditPayload := buildAuditPayload(uid, "", family.String(), "", "ok")
		if _, err := tx.Exec(ctx, `
WITH u AS (
  UPDATE refresh_families SET revoked=TRUE WHERE family=$1 RETURNING family
),
o1 AS (
  INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
  VALUES ($2,'session.logged_out',$3,'auth.session.logged_out.v1',$4,'pending')
  ON CONFLICT (event_id) DO NOTHING RETURNING event_id
)
INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
VALUES ($5,'audit.session.logout',$3,'auth.audit.v1',$6,'pending')
ON CONFLICT (event_id) DO NOTHING`,
			family, outID, uid, string(loggedPayload), auditID, string(auditPayload),
		); err != nil {
			return auth.RevokedSession{}, fmt.Errorf("revoke family batch %v: %w", err, auth.ErrSessionInfra)
		}
		if err := tx.Commit(ctx); err != nil {
			return auth.RevokedSession{}, fmt.Errorf("commit %v: %w", err, auth.ErrSessionInfra)
		}
		s.redisRevokeBestEffort(ctx, "", family.String(), "", 15*time.Minute)
		return auth.RevokedSession{
			Result:   auth.LogoutLoggedOut,
			Identity: auth.LogoutIdentity{UserID: uid.String(), Family: family.String(), ExpiresAt: exp},
		}, nil
	}

	// Con sesiones: revoca todo en UN batch CTE (denylist por SELECT,
	// 1 RTT de escritura). Exp denylist = now+15min (peor caso Access).
	exp := now.Add(auth.AccessTTL)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return auth.RevokedSession{}, fmt.Errorf("begin %v: %w", err, auth.ErrSessionInfra)
	}
	defer tx.Rollback(ctx)
	firstSID, _ := uuid.Parse(rows[0].sid)
	firstJTI, _ := uuid.Parse(rows[0].jti)
	outID := uuid.New()
	auditID := uuid.New()
	loggedPayload := buildLoggedOutPayload(outID, uid, firstSID, family, firstJTI, false, now)
	auditPayload := buildAuditPayload(uid, rows[0].sid, family.String(), rows[0].jti, "ok")
	if _, err := tx.Exec(ctx, `
WITH u AS (
  UPDATE refresh_families SET revoked=TRUE WHERE family=$1 RETURNING family
),
j AS (
  INSERT INTO revoked_jtis (jti, user_id, expires_at)
  SELECT jti_actual, $2, $3 FROM sessions WHERE family=$1
  ON CONFLICT (jti) DO NOTHING RETURNING jti
),
d AS (
  DELETE FROM sessions WHERE family=$1 RETURNING sid
),
o1 AS (
  INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
  VALUES ($4,'session.logged_out',$2,'auth.session.logged_out.v1',$5,'pending')
  ON CONFLICT (event_id) DO NOTHING RETURNING event_id
)
INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
VALUES ($6,'audit.session.logout',$2,'auth.audit.v1',$7,'pending')
ON CONFLICT (event_id) DO NOTHING`,
		family, uid, exp, outID, string(loggedPayload), auditID, string(auditPayload),
	); err != nil {
		return auth.RevokedSession{}, fmt.Errorf("revoke batch %v: %w", err, auth.ErrSessionInfra)
	}
	if err := tx.Commit(ctx); err != nil {
		return auth.RevokedSession{}, fmt.Errorf("commit %v: %w", err, auth.ErrSessionInfra)
	}
	for _, r := range rows {
		s.redisRevokeBestEffort(ctx, r.sid, family.String(), r.jti, auth.AccessTTL)
	}
	if s.cache != nil {
		_ = s.cache.RevokeByHash(ctx, rows[0].sid, family.String(), rows[0].jti, refreshHash, auth.AccessTTL)
	}
	return auth.RevokedSession{
		Result: auth.LogoutLoggedOut,
		Identity: auth.LogoutIdentity{
			UserID: uid.String(), SID: rows[0].sid, JTI: rows[0].jti,
			Family: family.String(), ExpiresAt: exp,
		},
	}, nil
}

// buildLoggedOutPayload conserva el sobre usado desde CU-AUTH-04
// (event_id/event_type/occurred_at + payload anidado sin tokens).
func buildLoggedOutPayload(eventID, uid, sid, family, jti uuid.UUID, already bool, now time.Time) []byte {
	sidS, famS, jtiS := "", "", ""
	if sid != uuid.Nil {
		sidS = sid.String()
	}
	if family != uuid.Nil {
		famS = family.String()
	}
	if jti != uuid.Nil {
		jtiS = jti.String()
	}
	b, _ := json.Marshal(map[string]any{
		"event_id": eventID.String(), "event_type": "session.logged_out",
		"occurred_at": now.Format("2006-01-02T15:04:05Z"),
		"payload": map[string]any{
			"user_id": uid.String(), "sid": sidS,
			"family": famS, "jti": jtiS, "already": already,
		},
	})
	return b
}

// buildAuditPayload replica el sobre plano del AuditLogger de Kafka
// (topic auth.audit.v1): mismos campos, sin tokens, orden determinista.
func buildAuditPayload(uid uuid.UUID, sid, family, jti, result string) []byte {
	b, _ := json.Marshal(map[string]any{
		"action": "session.logout", "user_id": uid.String(),
		"sid": sid, "family": family, "jti": jti, "result": result,
	})
	return b
}

func (s *SessionRevoker) redisRevokeBestEffort(ctx context.Context, sid, family, jti string, ttl time.Duration) {
	if s.cache == nil {
		return
	}
	if sid == "" && family == "" && jti == "" {
		return
	}
	if err := s.cache.Revoke(ctx, sid, family, jti, ttl); err != nil {
		s.onFallback("redis-down")
	}
}

func isHex(s string) bool {
	for _, c := range s {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			continue
		}
		return false
	}
	return true
}

var _ auth.SessionRevoker = (*SessionRevoker)(nil)
