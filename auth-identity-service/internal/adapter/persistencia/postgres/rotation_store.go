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

// CombinedRotationStore implementa auth.RotationStore (CU-SES-04 T-08).
// PG verdad (CAS + chain + outbox) + espejo Redis best-effort.
// ReuseGlobal delega el corte a GlobalRevoker (SES-02, sin tocarlo) y luego
// registra evidencia reuse (P1 + email crítico) en segunda Tx: el corte
// durable va primero (dirección segura si la segunda falla).
type CombinedRotationStore struct {
	pool    *pgxpool.Pool
	cache   *redisadapter.RotationCache
	global  *GlobalRevoker
	onFallback func(reason string)
}

func NewCombinedRotationStore(pool *pgxpool.Pool, cache *redisadapter.RotationCache, global *GlobalRevoker, onFallback func(string)) *CombinedRotationStore {
	if onFallback == nil {
		onFallback = func(string) {}
	}
	return &CombinedRotationStore{pool: pool, cache: cache, global: global, onFallback: onFallback}
}

// Lookup resuelve hash→family+estado (lectura con contexto de emisión para
// re-firmar; join users por email para el eventual aviso crítico).
func (s *CombinedRotationStore) Lookup(ctx context.Context, refreshHash string) (auth.RotationLookup, error) {
	if len(refreshHash) != 64 || !isHex(refreshHash) {
		return auth.RotationLookup{}, auth.ErrRefreshNotFound
	}
	if s.pool == nil {
		return auth.RotationLookup{}, fmt.Errorf("no pool: %w", auth.ErrSessionInfra)
	}
	var st auth.FamilyState
	var sliding time.Time
	var isCur, isPar bool
	var amr, roles []string
	var rolesVer int
	var authTime time.Time
	var email, sidStr, curHash, parHash, famStr, uidStr string
	var counter int
	var absExp, rotAt time.Time
	var revoked bool
	var devHash string
	err := s.pool.QueryRow(ctx, `SELECT f.family::text, f.user_id::text, f.current_hash,
		f.parent_hash, f.counter, f.absolute_exp, f.revoked, f.last_rotated_at,
		f.device_hash, u.email_normalized,
		COALESCE(s.sid::text, ''), COALESCE(s.auth_time, f.absolute_exp - INTERVAL '90 days'),
		COALESCE(s.amr, '{pwd}'), COALESCE(s.roles, '{user}'), COALESCE(s.roles_ver, 0),
		h.expires_at,
		(h.hash = f.current_hash) AS is_cur, (h.hash = f.parent_hash) AS is_par
		FROM refresh_hashes h
		JOIN refresh_families f ON f.family = h.family
		JOIN users u ON u.id = f.user_id
		LEFT JOIN sessions s ON s.family = f.family
		WHERE h.hash = $1`, refreshHash).Scan(
		&famStr, &uidStr, &curHash, &parHash, &counter, &absExp, &revoked, &rotAt,
		&devHash, &email, &sidStr, &authTime, &amr, &roles, &rolesVer,
		&sliding, &isCur, &isPar)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return auth.RotationLookup{}, auth.ErrRefreshNotFound
		}
		return auth.RotationLookup{}, fmt.Errorf("lookup %v: %w", err, auth.ErrSessionInfra)
	}
	st = auth.FamilyState{
		Family: famStr, UserID: uidStr, SID: sidStr, CurrentHash: curHash,
		ParentHash: parHash, Counter: counter, AbsoluteExp: absExp.UTC(),
		Revoked: revoked, RotatedAt: rotAt.UTC(), DeviceHash: devHash, Email: email,
		AuthTime: authTime.UTC(), AMR: amr, Roles: roles, RolesVer: rolesVer,
	}
	return auth.RotationLookup{State: st, PresentedHash: refreshHash,
		SlidingExp: sliding.UTC(), CounterPresented: counterOfHash(refreshHash, curHash, parHash, counter),
		IsCurrent: isCur, IsParent: isPar}, nil
}

// counterOfHash infiere el counter del hash presentado (current→counter,
// parent→counter-1, antiguo→counter-2+... exacto solo para parent).
func counterOfHash(h, cur, par string, counter int) int {
	switch h {
	case cur:
		return counter
	case par:
		return counter - 1
	default:
		return counter - 2
	}
}

// RotateCAS persiste la rotación con CAS (0 filas → ErrConcurrent;
// revoked concurrente → ErrRefreshRevoked). Todo en UN batch CTE + 1 commit.
func (s *CombinedRotationStore) RotateCAS(ctx context.Context, in auth.RotateCASInput) (auth.RotatedPair, error) {
	if s.pool == nil {
		return auth.RotatedPair{}, fmt.Errorf("no pool: %w", auth.ErrSessionInfra)
	}
	now := time.Now().UTC()
	newCounter := in.State.Counter + 1

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return auth.RotatedPair{}, fmt.Errorf("begin %v: %w", err, auth.ErrSessionInfra)
	}
	defer tx.Rollback(ctx)

	// Re-lectura fresca FOR UPDATE (serializa races por family).
	// COALESCE cubre families huérfanas sin sesión (revoked viejas).
	var curHash string
	var revoked bool
	var absExp time.Time
	var oldJTI uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT f.current_hash, f.revoked, f.absolute_exp,
		COALESCE(s.jti_actual, '00000000-0000-0000-0000-000000000000'::uuid)
		FROM refresh_families f
		LEFT JOIN sessions s ON s.family = f.family
		WHERE f.family=$1::uuid FOR UPDATE OF f`,
		in.State.Family).Scan(&curHash, &revoked, &absExp, &oldJTI); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return auth.RotatedPair{}, auth.ErrRefreshRevoked
		}
		return auth.RotatedPair{}, fmt.Errorf("refetch %v: %w", err, auth.ErrSessionInfra)
	}
	if revoked {
		return auth.RotatedPair{}, auth.ErrRefreshRevoked
	}
	if !now.Before(absExp) {
		return auth.RotatedPair{}, auth.ErrRefreshExpired
	}
	if curHash != in.OldHash {
		return auth.RotatedPair{}, auth.ErrRefreshConcurrent
	}

	outID := uuid.New()
	auditID := uuid.New()
	rotPayload := buildRotatedPayload(outID, in.State.UserID, in.State.SID, in.State.Family, newCounter, now, in.NewHash)
	auditPayload := buildRotateAuditPayload(in.State.UserID, in.State.Family, newCounter, "ok")
	// Mapeo: $1 family, $2 newHash, $3 oldHash, $4 counter, $5 now, $6 fp,
	// $7 slidingTo, $8 newJTI, $9 oldJTI, $10 uid, $11 accessExp,
	// $12 outID, $13 rotPayload, $14 auditID, $15 auditPayload.
	if _, err := tx.Exec(ctx, `
WITH u AS (
  UPDATE refresh_families
  SET current_hash=$2, parent_hash=$3, counter=$4, last_rotated_at=$5, device_hash=$6
  WHERE family=$1::uuid AND current_hash=$3 RETURNING family
),
h AS (
  INSERT INTO refresh_hashes (hash, family, counter, expires_at)
  VALUES ($2,$1::uuid,$4,$7) ON CONFLICT (hash) DO NOTHING RETURNING hash
),
d AS (
  UPDATE sessions SET jti_actual=$8::uuid, last_seen=$5 WHERE family=$1::uuid RETURNING sid
),
j AS (
  INSERT INTO revoked_jtis (jti, user_id, expires_at)
  VALUES ($9,$10::uuid,$11) ON CONFLICT (jti) DO NOTHING RETURNING jti
),
o1 AS (
  INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
  VALUES ($12,'session.rotated',$10::uuid,'auth.session.rotated.v1',$13,'pending')
  ON CONFLICT (event_id) DO NOTHING RETURNING event_id
)
INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
VALUES ($14,'audit.session.rotate',$10::uuid,'auth.audit.v1',$15,'pending')
ON CONFLICT (event_id) DO NOTHING`,
		in.State.Family, in.NewHash, in.OldHash, newCounter, now, in.PresentedFP,
		in.SlidingTo, in.NewPair.JTI,
		oldJTI, in.State.UserID, now.Add(auth.AccessTTL),
		outID, string(rotPayload), auditID, string(auditPayload),
	); err != nil {
		return auth.RotatedPair{}, fmt.Errorf("rotate batch %v: %w", err, auth.ErrSessionInfra)
	}
	// CAS perdido (0 filas en u por carrera microsegundo): detecta por
	// counter? El WHERE current_hash=old ya filtra; si llegó aquí, ganó.
	if err := tx.Commit(ctx); err != nil {
		return auth.RotatedPair{}, fmt.Errorf("commit %v: %w", err, auth.ErrSessionInfra)
	}

	// Espejo Redis best-effort (PG es la verdad).
	if s.cache != nil {
		if rerr := s.cache.RotateMirror(ctx, in.NewPair.SID, in.State.Family,
			in.OldHash, in.NewHash, oldJTI.String(), in.NewPair.JTI,
			auth.DenylistTTL(in.NewPair.ExpiresAt, now)); rerr != nil {
			s.onFallback("redis-down")
		}
	}
	out := in.NewPair
	out.Counter = newCounter
	return out, nil
}

// ExpireFamily marca revoked best-effort (sliding/absolute pasado).
func (s *CombinedRotationStore) ExpireFamily(ctx context.Context, family string) error {
	if s.pool == nil {
		return nil
	}
	_, _ = s.pool.Exec(ctx, `UPDATE refresh_families SET revoked=TRUE
		WHERE family=$1::uuid AND revoked=FALSE`, family)
	return nil
}

// IncrFlaps delega al contador Redis (error → el servicio hace fail-open).
func (s *CombinedRotationStore) IncrFlaps(ctx context.Context, oldHash string) (int64, error) {
	if s.cache == nil {
		return 0, fmt.Errorf("no cache: %w", auth.ErrSessionInfra)
	}
	return s.cache.IncrFlaps(ctx, oldHash)
}

// ReuseGlobal ejecuta el corte SES-02 y luego la evidencia del robo (P1 +
// email crítico con ambos devices). El corte va primero: si la evidencia
// falla, el usuario ya está a salvo (dirección segura).
func (s *CombinedRotationStore) ReuseGlobal(ctx context.Context, in auth.ReuseGlobalInput) (auth.GlobalRevokeResult, error) {
	if s.global == nil {
		return auth.GlobalRevokeResult{}, fmt.Errorf("no global revoker: %w", auth.ErrSessionInfra)
	}
	now := time.Now().UTC()
	res, gerr := s.global.RevokeAll(ctx, in.State.UserID, in.IP)
	if gerr != nil {
		return auth.GlobalRevokeResult{}, gerr
	}
	outID := uuid.New()
	auditID := uuid.New()
	mailID := uuid.New()
	reusePayload := buildReusePayload(outID, in, now)
	auditPayload := buildReuseAuditPayload(in, now)
	mailSubject := "Detectamos uso indebido: cerramos todo"
	mailBody := "Hola,\n\nDetectamos uso indebido de tu sesión el " +
		now.UTC().Format("2006-01-02 15:04 UTC") +
		" y cerramos TODAS tus sesiones por seguridad.\n\n" +
		"Uso legítimo anterior (huella " + auth.HashPrefix8(in.State.CurrentHash) + ") vs uso detectado ahora (huella " +
		auth.HashPrefix8(in.PresentedHash) + ").\n\nCambia tu contraseña ahora desde /login o /forgot.\n"
	toEmail := in.State.Email
	if _, err := s.pool.Exec(ctx, `
WITH o1 AS (
  INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
  VALUES ($1,'session.reuse_detected',$2,'auth.session.reuse_detected.v1',$3,'pending')
  ON CONFLICT (event_id) DO NOTHING RETURNING event_id
),
o2 AS (
  INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
  VALUES ($4,'audit.session.reuse',$2,'auth.audit.v1',$5,'pending')
  ON CONFLICT (event_id) DO NOTHING RETURNING event_id
)
INSERT INTO email_queue (id, to_email, subject, body_text, status)
VALUES ($6,$7,$8,$9,'pending') ON CONFLICT (id) DO NOTHING`,
		outID, in.State.UserID, string(reusePayload),
		auditID, string(auditPayload),
		mailID, toEmail, mailSubject, mailBody,
	); err != nil {
		// Evidencia perdida, corte intacto: se reporta pero el 401 sale igual.
		s.onFallback("reuse-evidence-down")
		return res, fmt.Errorf("reuse evidence %v: %w", err, auth.ErrSessionInfra)
	}
	return res, nil
}

func buildRotatedPayload(eventID uuid.UUID, userID, sid, family string, counter int, now time.Time, newHash string) []byte {
	b, _ := json.Marshal(map[string]any{
		"event_id": eventID.String(), "event_type": "session.rotated",
		"occurred_at": now.Format("2006-01-02T15:04:05Z"),
		"payload": map[string]any{
			"user_id": userID, "sid": sid, "family": family, "counter": counter,
			"hash_prefix": auth.HashPrefix8(newHash),
		},
	})
	return b
}

func buildRotateAuditPayload(userID, family string, counter int, result string) []byte {
	b, _ := json.Marshal(map[string]any{
		"action": "session.rotate", "user_id": userID, "family": family,
		"counter": counter, "result": result,
	})
	return b
}

func buildReusePayload(eventID uuid.UUID, in auth.ReuseGlobalInput, now time.Time) []byte {
	b, _ := json.Marshal(map[string]any{
		"event_id": eventID.String(), "event_type": "session.reuse_detected",
		"occurred_at": now.Format("2006-01-02T15:04:05Z"),
		"payload": map[string]any{
			"user_id": in.State.UserID, "family": in.State.Family,
			"counter_presented": in.CounterPresented, "counter_current": in.State.Counter,
			"device_presented": "sha256:" + auth.HashPrefix8(in.PresentedDevice),
			"device_current": "sha256:" + auth.HashPrefix8(in.State.DeviceHash),
		},
	})
	return b
}

func buildReuseAuditPayload(in auth.ReuseGlobalInput, now time.Time) []byte {
	b, _ := json.Marshal(map[string]any{
		"action": "session.reuse", "user_id": in.State.UserID, "family": in.State.Family,
		"counter_presented": in.CounterPresented, "counter_current": in.State.Counter,
		"result": "compromised",
	})
	_ = now
	return b
}

var _ auth.RotationStore = (*CombinedRotationStore)(nil)
