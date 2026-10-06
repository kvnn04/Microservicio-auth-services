package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/user"
	redisadapter "auth-identity-service/internal/adapter/persistencia/redis"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CombinedPasswordHistoryStore implementa auth.PasswordHistoryStore.
// RotateTx: re-chequeo optimista de base (TOCTOU por password_ver) +
// INSERT history(old) + UPDATE users(new,ver+1) + revoke pares + outbox +
// email, todo en UNA Tx; Redis DEL pares post-commit (best-effort).
type CombinedPasswordHistoryStore struct {
	pool     *pgxpool.Pool
	sessions *redisadapter.SessionCache
	frontURL string
	onFallback func(reason string)
}

func NewCombinedPasswordHistoryStore(pool *pgxpool.Pool, sessions *redisadapter.SessionCache, frontURL string, onFallback func(string)) *CombinedPasswordHistoryStore {
	if onFallback == nil {
		onFallback = func(string) {}
	}
	return &CombinedPasswordHistoryStore{pool: pool, sessions: sessions, frontURL: frontURL, onFallback: onFallback}
}

// Current resuelve cuenta para rotar (hash+ver+status+email).
func (s *CombinedPasswordHistoryStore) Current(ctx context.Context, userID string) (*auth.ChangeAccount, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("bad user id: %w", auth.ErrSessionInfra)
	}
	var a auth.ChangeAccount
	var status string
	var pwHash sql.NullString
	var ver int
	var email string
	if err := s.pool.QueryRow(ctx, `SELECT email_normalized, password_hash,
		COALESCE(password_ver, 1), status FROM users WHERE id=$1`,
		uid).Scan(&email, &pwHash, &ver, &status); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("no account: %w", auth.ErrSessionInfra)
		}
		return nil, fmt.Errorf("select user %v: %w", err, auth.ErrSessionInfra)
	}
	a.ID = uid.String()
	a.Email = email
	a.Hash = pwHash.String
	a.Ver = ver
	a.Status = user.Status(status)
	return &a, nil
}

// LastN últimos N hashes (desc). Tabla puede no existir en DBs viejas → vacía.
func (s *CombinedPasswordHistoryStore) LastN(ctx context.Context, userID string, n int) ([]string, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("bad user id: %w", auth.ErrSessionInfra)
	}
	if n <= 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT hash FROM password_history
		WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2`, uid, n)
	if err != nil {
		return nil, fmt.Errorf("select history %v: %w", err, auth.ErrSessionInfra)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if rerr := rows.Scan(&h); rerr == nil {
			out = append(out, h)
		}
	}
	return out, rows.Err()
}

// RotateTx rota en Tx atómica preservando la sesión actual (keepSID).
// TOCTOU: si la base o la versión se movieron → ErrPasswordReused opaco.
func (s *CombinedPasswordHistoryStore) RotateTx(ctx context.Context, userID, oldHash, newHash string, expectedVer int, keepSID, requestID string) (int, int, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return 0, 0, auth.ErrPasswordReused
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("begin %v: %w", err, auth.ErrSessionInfra)
	}
	defer tx.Rollback(ctx)

	var curHash sql.NullString
	var curVer int
	var emailNorm string
	if err := tx.QueryRow(ctx, `SELECT password_hash, COALESCE(password_ver,1),
		email_normalized FROM users WHERE id=$1 FOR UPDATE`,
		uid).Scan(&curHash, &curVer, &emailNorm); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, 0, auth.ErrPasswordReused
		}
		return 0, 0, fmt.Errorf("select user %v: %w", err, auth.ErrSessionInfra)
	}
	if !auth.SameHash(curHash.String, oldHash) || curVer != expectedVer {
		return 0, 0, auth.ErrPasswordReused // base movida por carrera.
	}
	now := time.Now().UTC()
	if _, err := tx.Exec(ctx, `INSERT INTO password_history (user_id, hash) VALUES ($1,$2)`,
		uid, curHash.String); err != nil {
		return 0, 0, fmt.Errorf("insert history %v: %w", err, auth.ErrSessionInfra)
	}
	newVer := curVer + 1
	if _, err := tx.Exec(ctx, `UPDATE users SET password_hash=$2, password_algo='argon2id',
		password_ver=$3, federated_only=FALSE, updated_at=$4 WHERE id=$1 AND COALESCE(password_ver,1)=$5`,
		uid, newHash, newVer, now, expectedVer); err != nil {
		return 0, 0, fmt.Errorf("update password %v: %w", err, auth.ErrSessionInfra)
	}

	// Familia a preservar (sesión actual); "" → revoca todo (fail-closed).
	keepFamily := ""
	if keepSID != "" {
		var fam uuid.UUID
		if ferr := tx.QueryRow(ctx, `SELECT family FROM sessions
			WHERE sid=$1::uuid AND user_id=$2`, keepSID, uid).Scan(&fam); ferr == nil {
			keepFamily = fam.String()
		}
	}
	type sessRef struct{ sid, fam, jti string }
	var refs []sessRef
	rows, err := tx.Query(ctx, `SELECT sid::text, family::text, jti_actual::text FROM sessions
		WHERE user_id=$1 AND ($2='' OR sid::text<>$2)`, uid, keepSID)
	if err == nil {
		for rows.Next() {
			var r sessRef
			if rerr := rows.Scan(&r.sid, &r.fam, &r.jti); rerr == nil {
				refs = append(refs, r)
			}
		}
		rows.Close()
	}
	if keepFamily == "" {
		_, _ = tx.Exec(ctx, `UPDATE refresh_families SET revoked=TRUE WHERE user_id=$1`, uid)
	} else {
		_, _ = tx.Exec(ctx, `UPDATE refresh_families SET revoked=TRUE WHERE user_id=$1 AND family<>$2::uuid`, uid, keepFamily)
	}
	if keepSID == "" {
		_, _ = tx.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1`, uid)
	} else {
		_, _ = tx.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1 AND sid<>$2::uuid`, uid, keepSID)
	}
	peers := len(refs)

	changedPayload, _ := json.Marshal(map[string]any{
		"user_id": uid.String(), "via": "change", "password_ver": newVer, "request_id": requestID,
	})
	if _, err := tx.Exec(ctx, `INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
		VALUES ($1,'password.changed',$2,'auth.password.v1',$3,'pending')`,
		uuid.New(), uid, string(changedPayload)); err != nil {
		return 0, 0, fmt.Errorf("insert outbox %v: %w", err, auth.ErrSessionInfra)
	}
	revokedPayload, _ := json.Marshal(map[string]any{
		"user_id": uid.String(), "kept_sid": keepSID, "kept_family": keepFamily,
		"count": peers,
	})
	if _, err := tx.Exec(ctx, `INSERT INTO outbox (event_id, event_type, aggregate_id, topic, payload, status)
		VALUES ($1,'session.revoked_peers',$2,'auth.session.revoked_peers.v1',$3,'pending')`,
		uuid.New(), uid, string(revokedPayload)); err != nil {
		return 0, 0, fmt.Errorf("insert revoke outbox %v: %w", err, auth.ErrSessionInfra)
	}
	changedBody := "Hola,\n\nCambiaste la contraseña de tu cuenta el " +
		now.Format("2006-01-02 15:04 UTC") +
		". Mantuvimos este dispositivo y cerramos " + itoaHist(peers) + " otra(s) sesión(es).\n\n" +
		"Si no fuiste tú, solicita un nuevo enlace de recuperación cuanto antes.\n"
	if _, err := tx.Exec(ctx, `INSERT INTO email_queue (id, to_email, subject, body_text, status)
		VALUES ($1,$2,'Cambiaste tu contraseña',$3,'pending')`,
		uuid.New(), emailNorm, changedBody); err != nil {
		return 0, 0, fmt.Errorf("insert email_queue %v: %w", err, auth.ErrSessionInfra)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, 0, fmt.Errorf("commit %v: %w", err, auth.ErrSessionInfra)
	}

	// Redis DEL pares post-commit (best-effort; PG es la verdad y las
	// claves huérfanas expiran por TTL).
	if s.sessions != nil && len(refs) > 0 {
		sids := make([]string, 0, len(refs))
		fams := make([]string, 0, len(refs))
		jtis := make([]string, 0, len(refs))
		for _, r := range refs {
			sids = append(sids, r.sid)
			fams = append(fams, r.fam)
			jtis = append(jtis, r.jti)
		}
		if derr := s.sessions.InvalidateSessions(ctx, sids, fams, jtis); derr != nil {
			s.onFallback("sessions-down")
		}
	}
	return newVer, peers, nil
}

func itoaHist(n int) string {
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

var _ auth.PasswordHistoryStore = (*CombinedPasswordHistoryStore)(nil)
