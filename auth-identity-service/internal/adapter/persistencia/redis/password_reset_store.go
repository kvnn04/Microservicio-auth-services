package redis

import (
	"context"
	"encoding/json"
	"time"

	"auth-identity-service/internal/domain/auth"

	"github.com/redis/go-redis/v9"
)

// Claves efímeras CU-CRED-01 (nunca PII/plano: solo hashes SHA-256 hex y UUIDs).
//
//	pwdreset:t:<token_hash>          JSON {user_id, exp, ctx} EX 900 NX
//	pwdreset:active:<user_id>        <token_hash> EX 900 (sobrescribe, 1 activo)
//	pwdreset:att:<hash>              contador intentos EX 900
//	pwdreset:sent:<key>              unix envío EX 86400 (cooldown 60s)
//	pwdreset:count:<key>:<yyyy-mm-dd> contador cuota EX 172800
func pwdResetTKey(h string) string      { return "pwdreset:t:" + h }
func pwdResetActiveKey(u string) string { return "pwdreset:active:" + u }
func pwdResetAttKey(h string) string    { return "pwdreset:att:" + h }
func pwdResetSentKey(k string) string   { return "pwdreset:sent:" + k }

func pwdResetCountKey(k string) string {
	return "pwdreset:count:" + k + ":" + time.Now().UTC().Format("2006-01-02")
}

type pwdResetCachedRecord struct {
	UserID  string            `json:"user_id"`
	ExpUnix int64             `json:"exp"`
	Ctx     auth.PlessContext `json:"ctx"`
}

// PasswordResetCache es la verdad rápida (Redis) del puerto PasswordResetStore.
type PasswordResetCache struct {
	client *redis.Client
}

func NewPasswordResetCache(client *redis.Client) *PasswordResetCache {
	return &PasswordResetCache{client: client}
}

func (c *PasswordResetCache) Put(ctx context.Context, rec *auth.PasswordResetRecord) error {
	if c.client == nil {
		return redis.ErrClosed
	}
	ttl := time.Until(rec.ExpiresAt)
	if ttl <= 0 {
		return nil
	}
	if ttl > auth.PwdResetTTL {
		ttl = auth.PwdResetTTL
	}
	body, _ := json.Marshal(pwdResetCachedRecord{
		UserID: rec.UserID, ExpUnix: rec.ExpiresAt.Unix(), Ctx: rec.Ctx,
	})
	pipe := c.client.Pipeline()
	pipe.SetNX(ctx, pwdResetTKey(rec.TokenHash), string(body), ttl)
	pipe.Set(ctx, pwdResetActiveKey(rec.UserID), rec.TokenHash, ttl)
	_, err := pipe.Exec(ctx)
	return err
}

// Get busca por hash. hit=false si miss (fallback Postgres).
func (c *PasswordResetCache) Get(ctx context.Context, hash string) (rec *auth.PasswordResetRecord, hit bool, err error) {
	if c.client == nil {
		return nil, false, redis.ErrClosed
	}
	raw, err := c.client.Get(ctx, pwdResetTKey(hash)).Result()
	if err == redis.Nil {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var cr pwdResetCachedRecord
	if jerr := json.Unmarshal([]byte(raw), &cr); jerr != nil {
		return nil, false, nil
	}
	att, _ := c.client.Get(ctx, pwdResetAttKey(hash)).Int()
	return &auth.PasswordResetRecord{
		UserID: cr.UserID, TokenHash: hash,
		ExpiresAt: time.Unix(cr.ExpUnix, 0).UTC(), Attempts: att, Ctx: cr.Ctx,
	}, true, nil
}

// Invalidate borra t/active/att (Lua atómico, best-effort).
func (c *PasswordResetCache) Invalidate(ctx context.Context, rec *auth.PasswordResetRecord) {
	if c.client == nil || rec == nil {
		return
	}
	script := redis.NewScript(`
		redis.call('DEL', KEYS[1])
		redis.call('DEL', KEYS[2])
		redis.call('DEL', KEYS[3])
		return 1`)
	_ = script.Run(ctx, c.client,
		[]string{pwdResetTKey(rec.TokenHash), pwdResetActiveKey(rec.UserID), pwdResetAttKey(rec.TokenHash)}).Err()
}

// IncrAttempts suma intento; retorna conteo (para quemado en >=3).
func (c *PasswordResetCache) IncrAttempts(ctx context.Context, hash string) (int, error) {
	if c.client == nil {
		return 0, redis.ErrClosed
	}
	n, err := c.client.Incr(ctx, pwdResetAttKey(hash)).Result()
	if err != nil {
		return 0, err
	}
	_, _ = c.client.Expire(ctx, pwdResetAttKey(hash), auth.PwdResetTTL).Result()
	return int(n), nil
}

// QuotaCheck evalúa cooldown 60s + cuota 5/24h por clave (solo lectura).
func (c *PasswordResetCache) QuotaCheck(ctx context.Context, key string) (allowed bool, retryAfter time.Duration, err error) {
	if c.client == nil {
		return false, 0, redis.ErrClosed
	}
	if v, err := c.client.Get(ctx, pwdResetSentKey(key)).Int64(); err == nil {
		if elapsed := time.Since(time.Unix(v, 0)); elapsed < auth.PwdResetCooldown {
			return false, auth.PwdResetCooldown - elapsed, nil
		}
	} else if err != redis.Nil {
		return false, 0, err
	}
	n, err := c.client.Get(ctx, pwdResetCountKey(key)).Int()
	if err != nil && err != redis.Nil {
		return false, 0, err
	}
	if n >= auth.PwdResetMaxDay {
		return false, time.Hour, nil
	}
	return true, 0, nil
}

// NoteSent registra envío (cooldown + cuota). Best-effort post-commit.
func (c *PasswordResetCache) NoteSent(ctx context.Context, key string) {
	if c.client == nil {
		return
	}
	now := time.Now().UTC().Unix()
	pipe := c.client.Pipeline()
	pipe.Set(ctx, pwdResetSentKey(key), now, 24*time.Hour)
	pipe.Incr(ctx, pwdResetCountKey(key))
	pipe.Expire(ctx, pwdResetCountKey(key), 48*time.Hour)
	_, _ = pipe.Exec(ctx)
}
