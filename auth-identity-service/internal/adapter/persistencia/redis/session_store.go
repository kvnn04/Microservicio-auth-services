package redis

import (
	"context"
	"encoding/json"
	"time"

	"auth-identity-service/internal/domain/auth"

	"github.com/redis/go-redis/v9"
)

// Claves CU-AUTH-04 (sin PII: solo UUIDs + hashes):
//
//	sess:<sid>  JSON {user,family,jti,device,label,ip_masked,location,
//	           created_at,last_seen} EX 7776000 (90d) — espejo para el
//	           fast-path de lista CU-SES-03 (all-or-nothing con PG verdad)
//	fam:<family> {current_hash} EX 7776000
//	jti:<jti>   1 EX 900 (denylist corta SES-01, TTL Access)
type sessionCacheVal struct {
	User      string `json:"user"`
	Family    string `json:"family"`
	JTI       string `json:"jti"`
	Device    string `json:"device"`
	Label     string `json:"label,omitempty"`
	IPMasked  string `json:"ip_masked,omitempty"`
	Location  string `json:"location,omitempty"`
	CreatedAt int64  `json:"created_at"`
	LastSeen  int64  `json:"last_seen"`
}

func sessKey(sid string) string { return "sess:" + sid }
func famKey(fam string) string  { return "fam:" + fam }
func jtiKey(jti string) string  { return "jti:" + jti }

// RefreshByHashKey índice inverso hash→family (CU-SES-01 RevokeByRefreshHash).
// Se escribe en Issue (aquí) para localizar sin SCAN; si falta (sesiones
// viejas), el Revoker cae a PG (verdad).
func RefreshByHashKey(hash string) string { return "refresh:by_hash:" + hash }

// SessionCache implementa auth.SessionCache (write-through best-effort).
// Error NUNCA bloquea la entrega: el servicio lo cuenta como fallback
// y PG sigue siendo verdad (rehidrata al recuperar).
type SessionCache struct {
	client *redis.Client
}

func NewSessionCache(client *redis.Client) *SessionCache {
	return &SessionCache{client: client}
}

func (c *SessionCache) Save(ctx context.Context, sess auth.Session, fam auth.RefreshFamily, jti string) error {
	if c.client == nil {
		return redis.ErrClosed
	}
	val, _ := json.Marshal(sessionCacheVal{
		User: sess.UserID, Family: sess.Family, JTI: sess.JTI, Device: sess.DeviceHash,
		Label: sess.DeviceLabel, IPMasked: sess.IPMasked, Location: sess.Location,
		CreatedAt: sess.CreatedAt.Unix(), LastSeen: sess.LastSeen.Unix(),
	})
	pipe := c.client.Pipeline()
	pipe.Set(ctx, sessKey(sess.SID), string(val), 90*24*time.Hour)
	pipe.Set(ctx, famKey(fam.Family), fam.CurrentHash, 90*24*time.Hour)
	pipe.Set(ctx, jtiKey(jti), "1", 15*time.Minute)
	// CU-SES-01: índice inverso para logout por refresh sin SCAN.
	// Best-effort (si falla, RevokeByRefreshHash cae a PG).
	if fam.CurrentHash != "" {
		pipe.Set(ctx, RefreshByHashKey(fam.CurrentHash), fam.Family, 90*24*time.Hour)
	}
	// CU-SES-02: índice sids-por-usuario para el barrido global.
	// Miembros muertos (logout individual sin SREM) los tolera el sweep
	// (DEL de inexistente es no-op) y los purga al borrar la clave.
	if sess.UserID != "" && sess.SID != "" {
		pipe.SAdd(ctx, SessByUserKey(sess.UserID), sess.SID)
		pipe.Expire(ctx, SessByUserKey(sess.UserID), byUserTTL)
	}
	_, err := pipe.Exec(ctx)
	return err
}

// Rehydrate re-escribe desde PG tras caída (el servicio lo invoca best-effort).
func (c *SessionCache) Rehydrate(ctx context.Context, sess auth.Session, fam auth.RefreshFamily) error {
	return c.Save(ctx, sess, fam, sess.JTI)
}

// InvalidateSessions borra sess/fam/jti de una lista (corte global CU-CRED-01).
// Best-effort post-commit: el error se cuenta como fallback, no revierte.
func (c *SessionCache) InvalidateSessions(ctx context.Context, sids, families, jtis []string) error {
	if c.client == nil {
		return redis.ErrClosed
	}
	if len(sids) == 0 && len(families) == 0 && len(jtis) == 0 {
		return nil
	}
	pipe := c.client.Pipeline()
	for _, s := range sids {
		pipe.Del(ctx, sessKey(s))
	}
	for _, f := range families {
		pipe.Del(ctx, famKey(f))
	}
	for _, j := range jtis {
		pipe.Del(ctx, jtiKey(j))
	}
	_, err := pipe.Exec(ctx)
	return err
}

var _ auth.SessionCache = (*SessionCache)(nil)
