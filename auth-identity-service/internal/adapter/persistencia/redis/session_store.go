package redis

import (
	"context"
	"encoding/json"
	"time"

	"auth-identity-service/internal/domain/auth"

	"github.com/redis/go-redis/v9"
)

// Claves CU-AUTH-04 (sin PII: solo UUIDs + hashes):
//   sess:<sid>  JSON {user,family,jti,device} EX 7776000 (90d)
//   fam:<family> {current_hash} EX 7776000
//   jti:<jti>   1 EX 900 (denylist corta SES-01, TTL Access)
type sessionCacheVal struct {
	User   string `json:"user"`
	Family string `json:"family"`
	JTI    string `json:"jti"`
	Device string `json:"device"`
}

func sessKey(sid string) string   { return "sess:" + sid }
func famKey(fam string) string    { return "fam:" + fam }
func jtiKey(jti string) string    { return "jti:" + jti }

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
	})
	pipe := c.client.Pipeline()
	pipe.Set(ctx, sessKey(sess.SID), string(val), 90*24*time.Hour)
	pipe.Set(ctx, famKey(fam.Family), fam.CurrentHash, 90*24*time.Hour)
	pipe.Set(ctx, jtiKey(jti), "1", 15*time.Minute)
	_, err := pipe.Exec(ctx)
	return err
}

// Rehydrate re-escribe desde PG tras caída (el servicio lo invoca best-effort).
func (c *SessionCache) Rehydrate(ctx context.Context, sess auth.Session, fam auth.RefreshFamily) error {
	return c.Save(ctx, sess, fam, sess.JTI)
}

var _ auth.SessionCache = (*SessionCache)(nil)
