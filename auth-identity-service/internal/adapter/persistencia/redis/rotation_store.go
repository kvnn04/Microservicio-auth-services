package redis

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
)

// Claves CU-SES-04 (rotación):
//
//	idempotency:refresh:<reqID>  {access,refresh,exp,sid} EX 60 — ÚNICO
//	                             lugar que guarda Refresh plano (ventana
//	                             mínima para gracia idempotente).
//	concurrent:<oldHash>          contador EX 10 (anti-flapping: al 4º global).
const (
	idemRefreshTTL = 60 * time.Second
	flapTTL        = 10 * time.Second
)

// IdemRefreshPair par guardado para replay mismo-RequestID.
type IdemRefreshPair struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
	Exp     int64  `json:"exp"`
	SID     string `json:"sid"`
}

// RotationCache espejo de rotación + idempotencia + flaps (T-08).
type RotationCache struct {
	client *redis.Client
}

func NewRotationCache(client *redis.Client) *RotationCache {
	return &RotationCache{client: client}
}

func idemRefreshKey(reqID string) string { return "idempotency:refresh:" + reqID }
func flapKey(oldHash string) string      { return "concurrent:" + oldHash }

// GetIdem recupera el par del replay (ok=false si miss/error).
func (c *RotationCache) GetIdem(ctx context.Context, reqID string) (IdemRefreshPair, bool) {
	var zero IdemRefreshPair
	if c.client == nil || reqID == "" {
		return zero, false
	}
	raw, err := c.client.Get(ctx, idemRefreshKey(reqID)).Result()
	if err != nil {
		return zero, false
	}
	var p IdemRefreshPair
	if jerr := json.Unmarshal([]byte(raw), &p); jerr != nil {
		return zero, false
	}
	if p.Access == "" || p.Refresh == "" || p.SID == "" || p.Exp <= 0 {
		return zero, false
	}
	return p, true
}

// PutIdem guarda el par 60s (falla silenciosa → gracia degradada a 409).
func (c *RotationCache) PutIdem(ctx context.Context, reqID string, p IdemRefreshPair) {
	if c.client == nil || reqID == "" {
		return
	}
	b, _ := json.Marshal(p)
	_ = c.client.Set(ctx, idemRefreshKey(reqID), string(b), idemRefreshTTL).Err()
}

// IncrFlaps cuenta eventos concurrentes con el viejo (EX 10s).
func (c *RotationCache) IncrFlaps(ctx context.Context, oldHash string) (int64, error) {
	if c.client == nil {
		return 0, redis.ErrClosed
	}
	n, err := c.client.Incr(ctx, flapKey(oldHash)).Result()
	if err != nil {
		return 0, err
	}
	_, _ = c.client.Expire(ctx, flapKey(oldHash), flapTTL).Result()
	return n, nil
}

// RotateMirror actualiza el espejo tras CAS: fam→nuevo, by_hash nuevo,
// by_hash viejo fuera, jti viejo denylisteado, sess con JTI nuevo.
func (c *RotationCache) RotateMirror(ctx context.Context, sid, family, oldHash, newHash, oldJTI, newJTI string, ttl time.Duration) error {
	if c.client == nil {
		return redis.ErrClosed
	}
	if ttl <= 0 {
		ttl = time.Second
	}
	pipe := c.client.Pipeline()
	if family != "" && newHash != "" {
		pipe.Set(ctx, famKey(family), newHash, 90*24*time.Hour)
		pipe.Set(ctx, RefreshByHashKey(newHash), family, 90*24*time.Hour)
	}
	if oldHash != "" {
		pipe.Del(ctx, RefreshByHashKey(oldHash))
	}
	if oldJTI != "" {
		pipe.Set(ctx, jtiKey(oldJTI), "revoked", ttl)
	}
	if sid != "" && newJTI != "" {
		// Refresca el JTI del JSON sin re-leer PG (best-effort).
		raw, err := c.client.Get(ctx, sessKey(sid)).Result()
		if err == nil && raw != "" {
			var v sessionCacheVal
			if jerr := json.Unmarshal([]byte(raw), &v); jerr == nil {
				v.JTI = newJTI
				v.LastSeen = time.Now().UTC().Unix()
				if nb, merr := json.Marshal(v); merr == nil {
					pipe.Set(ctx, sessKey(sid), string(nb), 90*24*time.Hour)
				}
			}
		}
	}
	_, err := pipe.Exec(ctx)
	return err
}
