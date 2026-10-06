package redis

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"auth-identity-service/internal/domain/auth"

	"github.com/redis/go-redis/v9"
)

// SessionListCache fast-path de lista + revoke selectivo (CU-SES-03 T-08).
// La lista es all-or-nothing: si falta un miembro del índice o un JSON
// está incompleto → (nil, error) y el llamador cae a PG (verdad ordenada).
type SessionListCache struct {
	client *redis.Client
}

func NewSessionListCache(client *redis.Client) *SessionListCache {
	return &SessionListCache{client: client}
}

// List reconstruye las vistas desde sess:* (orden last_seen DESC).
// Exige el set COMPLETO: len(views)==len(members) y todos parseables.
func (c *SessionListCache) List(ctx context.Context, userID string) ([]auth.SessionView, error) {
	if c.client == nil {
		return nil, redis.ErrClosed
	}
	members, err := c.client.SMembers(ctx, SessByUserKey(userID)).Result()
	if err != nil || len(members) == 0 {
		return nil, errOrMiss(err)
	}
	keys := make([]string, 0, len(members))
	for _, sid := range members {
		if sid == "" {
			return nil, errMiss()
		}
		keys = append(keys, sessKey(sid))
	}
	raws, err := c.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, err
	}
	views := make([]auth.SessionView, 0, len(members))
	for i, raw := range raws {
		s, ok := raw.(string)
		if !ok || s == "" {
			return nil, errMiss()
		}
		var v sessionCacheVal
		if jerr := json.Unmarshal([]byte(s), &v); jerr != nil {
			return nil, jerr
		}
		if v.User != userID || v.JTI == "" {
			return nil, errMiss()
		}
		views = append(views, auth.SessionView{
			SID:         members[i],
			DeviceLabel: orCacheUnknown(v.Label),
			IPMasked:    orCacheUnknown(v.IPMasked),
			Location:    v.Location,
			CreatedAt:   time.Unix(v.CreatedAt, 0).UTC(),
			LastSeen:    time.Unix(v.LastSeen, 0).UTC(),
		})
	}
	sort.Slice(views, func(i, j int) bool { return views[i].LastSeen.After(views[j].LastSeen) })
	return views, nil
}

// RevokeTarget limpia la huella del objetivo + denylistea su jti
// (EX=AccessTTL máx: el exp exacto no vive en PG) + SREM del índice.
func (c *SessionListCache) RevokeTarget(ctx context.Context, sid, family, jti, userID string) error {
	if c.client == nil {
		return redis.ErrClosed
	}
	pipe := c.client.Pipeline()
	if sid != "" {
		pipe.Del(ctx, sessKey(sid))
	}
	if family != "" {
		pipe.Del(ctx, famKey(family))
	}
	if jti != "" {
		pipe.Set(ctx, jtiKey(jti), "revoked", 15*time.Minute)
	}
	if userID != "" && sid != "" {
		pipe.SRem(ctx, SessByUserKey(userID), sid)
	}
	_, err := pipe.Exec(ctx)
	return err
}

// AcquireTouch debounce: SETNX touch:<sid> EX window. true = adquirida
// (debe tocar PG); false = debounced (otro request tocó hace <window).
func (c *SessionListCache) AcquireTouch(ctx context.Context, sid string, window time.Duration) (bool, error) {
	if c.client == nil {
		return false, redis.ErrClosed
	}
	return c.client.SetNX(ctx, touchKey(sid), "1", window).Result()
}

// MirrorLastSeen refresca last_seen del JSON cacheado (best-effort).
// Miss → nil (PG ya se actualizó; la próxima lista cae a PG o re-cachea).
func (c *SessionListCache) MirrorLastSeen(ctx context.Context, sid string, now time.Time) error {
	if c.client == nil {
		return redis.ErrClosed
	}
	raw, err := c.client.Get(ctx, sessKey(sid)).Result()
	if err != nil {
		return err
	}
	var v sessionCacheVal
	if jerr := json.Unmarshal([]byte(raw), &v); jerr != nil {
		return jerr
	}
	v.LastSeen = now.Unix()
	nb, _ := json.Marshal(v)
	ttl, terr := c.client.TTL(ctx, sessKey(sid)).Result()
	if terr != nil || ttl <= 0 {
		ttl = 90 * 24 * time.Hour
	}
	return c.client.Set(ctx, sessKey(sid), string(nb), ttl).Err()
}

func touchKey(sid string) string { return "touch:" + sid }

func orCacheUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func errMiss() error { return redis.Nil }

func errOrMiss(err error) error {
	if err != nil {
		return err
	}
	return redis.Nil
}

// IsMiss distingue miss normal (índice vacío/parcial → PG sin WARN)
// de error real Redis (→ WARN reconciliación).
func IsMiss(err error) bool {
	return err == nil || err == redis.Nil
}
