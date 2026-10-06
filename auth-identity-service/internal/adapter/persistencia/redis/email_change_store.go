package redis

import (
	"context"
	"encoding/json"
	"time"

	"auth-identity-service/internal/domain/user"

	"github.com/redis/go-redis/v9"
)

// Claves efímeras CU-CRED-03 (nunca PII/plano: solo hashes y UUIDs).
//   emailchange:t:<token_hash>          JSON {requester, new_norm, exp} EX 900 NX
//   emailchange:active:<requester>      <token_hash> EX 900 (sobrescribe, 1 activo)
//   emailchange:att:<hash>              contador intentos EX 900
//   emailchange:sent:<uid>              unix envío EX 86400 (cooldown 60s)
//   emailchange:count:<uid>:<yyyy-mm-dd> contador cuota EX 172800
func emailChangeTKey(h string) string      { return "emailchange:t:" + h }
func emailChangeActiveKey(u string) string { return "emailchange:active:" + u }
func emailChangeAttKey(h string) string    { return "emailchange:att:" + h }
func emailChangeSentKey(k string) string   { return "emailchange:sent:" + k }

func emailChangeCountKey(k string) string {
	return "emailchange:count:" + k + ":" + time.Now().UTC().Format("2006-01-02")
}

type emailChangeCachedRecord struct {
	Requester string `json:"requester"`
	NewNorm   string `json:"new_norm"`
	ExpUnix   int64  `json:"exp"`
}

// EmailChangeCache es la verdad rápida (Redis) del puerto EmailChangeStore.
type EmailChangeCache struct {
	client *redis.Client
}

func NewEmailChangeCache(client *redis.Client) *EmailChangeCache {
	return &EmailChangeCache{client: client}
}

func (c *EmailChangeCache) Put(ctx context.Context, rec *user.EmailChangeRecord) error {
	if c.client == nil {
		return redis.ErrClosed
	}
	ttl := time.Until(rec.ExpiresAt)
	if ttl <= 0 {
		return nil
	}
	if ttl > user.EmailChangeTTL {
		ttl = user.EmailChangeTTL
	}
	body, _ := json.Marshal(emailChangeCachedRecord{
		Requester: rec.RequesterID, NewNorm: rec.NewNormalized, ExpUnix: rec.ExpiresAt.Unix(),
	})
	pipe := c.client.Pipeline()
	pipe.SetNX(ctx, emailChangeTKey(rec.TokenHash), string(body), ttl)
	pipe.Set(ctx, emailChangeActiveKey(rec.RequesterID), rec.TokenHash, ttl)
	_, err := pipe.Exec(ctx)
	return err
}

// Get busca por hash. hit=false si miss (fallback Postgres).
func (c *EmailChangeCache) Get(ctx context.Context, hash string) (rec *user.EmailChangeRecord, hit bool, err error) {
	if c.client == nil {
		return nil, false, redis.ErrClosed
	}
	raw, err := c.client.Get(ctx, emailChangeTKey(hash)).Result()
	if err == redis.Nil {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var cr emailChangeCachedRecord
	if jerr := json.Unmarshal([]byte(raw), &cr); jerr != nil {
		return nil, false, nil
	}
	att, _ := c.client.Get(ctx, emailChangeAttKey(hash)).Int()
	return &user.EmailChangeRecord{
		RequesterID: cr.Requester, TokenHash: hash, NewNormalized: cr.NewNorm,
		ExpiresAt: time.Unix(cr.ExpUnix, 0).UTC(), Attempts: att,
	}, true, nil
}

// Invalidate borra t/active/att (Lua atómico, best-effort).
func (c *EmailChangeCache) Invalidate(ctx context.Context, rec *user.EmailChangeRecord) {
	if c.client == nil || rec == nil {
		return
	}
	script := redis.NewScript(`
		redis.call('DEL', KEYS[1])
		redis.call('DEL', KEYS[2])
		redis.call('DEL', KEYS[3])
		return 1`)
	_ = script.Run(ctx, c.client,
		[]string{emailChangeTKey(rec.TokenHash), emailChangeActiveKey(rec.RequesterID), emailChangeAttKey(rec.TokenHash)}).Err()
}

// IncrAttempts suma intento; retorna conteo (para quemado en >=3).
func (c *EmailChangeCache) IncrAttempts(ctx context.Context, hash string) (int, error) {
	if c.client == nil {
		return 0, redis.ErrClosed
	}
	n, err := c.client.Incr(ctx, emailChangeAttKey(hash)).Result()
	if err != nil {
		return 0, err
	}
	_, _ = c.client.Expire(ctx, emailChangeAttKey(hash), user.EmailChangeTTL).Result()
	return int(n), nil
}

// QuotaCheck evalúa cooldown 60s + cuota 5/24h por uid (solo lectura).
func (c *EmailChangeCache) QuotaCheck(ctx context.Context, userID string) (allowed bool, retryAfter time.Duration, err error) {
	if c.client == nil {
		return false, 0, redis.ErrClosed
	}
	if v, err := c.client.Get(ctx, emailChangeSentKey(userID)).Int64(); err == nil {
		if elapsed := time.Since(time.Unix(v, 0)); elapsed < user.EmailChangeCooldown {
			return false, user.EmailChangeCooldown - elapsed, nil
		}
	} else if err != redis.Nil {
		return false, 0, err
	}
	n, err := c.client.Get(ctx, emailChangeCountKey(userID)).Int()
	if err != nil && err != redis.Nil {
		return false, 0, err
	}
	if n >= user.EmailChangeMaxDay {
		return false, time.Hour, nil
	}
	return true, 0, nil
}

// NoteSent registra envío (cooldown + cuota). Best-effort post-commit.
func (c *EmailChangeCache) NoteSent(ctx context.Context, userID string) {
	if c.client == nil {
		return
	}
	now := time.Now().UTC().Unix()
	pipe := c.client.Pipeline()
	pipe.Set(ctx, emailChangeSentKey(userID), now, 24*time.Hour)
	pipe.Incr(ctx, emailChangeCountKey(userID))
	pipe.Expire(ctx, emailChangeCountKey(userID), 48*time.Hour)
	_, _ = pipe.Exec(ctx)
}
