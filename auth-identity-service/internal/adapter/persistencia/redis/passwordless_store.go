package redis

import (
	"context"
	"encoding/json"
	"time"

	"auth-identity-service/internal/domain/auth"

	"github.com/redis/go-redis/v9"
)

// Claves efímeras CU-AUTH-05 (nunca PII/plano: solo hashes SHA-256 hex y UUIDs).
//   pless:t:<token_hash>          JSON {user_id, otp_hash, exp, ctx} EX 600 NX
//   pless:o:<otp_hash>            <token_hash> EX 600 NX
//   pless:active:<user_id>        <token_hash> EX 600 (sobrescribe, 1 activo)
//   pless:att:<hash>              contador intentos EX 600
//   pless:sent:<key>              unix envío EX 86400 (cooldown 60s)
//   pless:count:<key>:<yyyy-mm-dd> contador cuota EX 172800
func plessTKey(h string) string      { return "pless:t:" + h }
func plessOKey(h string) string      { return "pless:o:" + h }
func plessActiveKey(u string) string { return "pless:active:" + u }
func plessAttKey(h string) string    { return "pless:att:" + h }
func plessSentKey(k string) string   { return "pless:sent:" + k }

func plessCountKey(k string) string {
	return "pless:count:" + k + ":" + time.Now().UTC().Format("2006-01-02")
}

type plessCachedRecord struct {
	UserID  string            `json:"user_id"`
	OTPHash string            `json:"otp_hash"`
	ExpUnix int64             `json:"exp"`
	Ctx     auth.PlessContext `json:"ctx"`
}

// PasswordlessCache es la verdad rápida (Redis) del puerto PasswordlessStore.
// Todos los métodos retornan redis.Nil/error si Redis cae para failover a Postgres.
type PasswordlessCache struct {
	client *redis.Client
}

func NewPasswordlessCache(client *redis.Client) *PasswordlessCache {
	return &PasswordlessCache{client: client}
}

func (c *PasswordlessCache) Put(ctx context.Context, rec *auth.PasswordlessRecord) error {
	if c.client == nil {
		return redis.ErrClosed
	}
	ttl := time.Until(rec.ExpiresAt)
	if ttl <= 0 {
		return nil
	}
	if ttl > auth.PlessTTL {
		ttl = auth.PlessTTL
	}
	body, _ := json.Marshal(plessCachedRecord{
		UserID: rec.UserID, OTPHash: rec.OTPHash,
		ExpUnix: rec.ExpiresAt.Unix(), Ctx: rec.Ctx,
	})
	pipe := c.client.Pipeline()
	pipe.SetNX(ctx, plessTKey(rec.TokenHash), string(body), ttl)
	if rec.OTPHash != "" {
		pipe.SetNX(ctx, plessOKey(rec.OTPHash), rec.TokenHash, ttl)
	}
	pipe.Set(ctx, plessActiveKey(rec.UserID), rec.TokenHash, ttl)
	_, err := pipe.Exec(ctx)
	return err
}

// Get busca por hash (link u OTP). hit=false si miss (fallback Postgres).
func (c *PasswordlessCache) Get(ctx context.Context, hash string) (rec *auth.PasswordlessRecord, hit bool, err error) {
	if c.client == nil {
		return nil, false, redis.ErrClosed
	}
	raw, err := c.client.Get(ctx, plessTKey(hash)).Result()
	tokenHash := hash
	if err == redis.Nil {
		// ¿Es OTP? o:<otp> → token_hash.
		th, oerr := c.client.Get(ctx, plessOKey(hash)).Result()
		if oerr == redis.Nil {
			return nil, false, nil // miss → fallback Postgres.
		}
		if oerr != nil {
			return nil, false, oerr // Redis caído → failover.
		}
		raw, err = c.client.Get(ctx, plessTKey(th)).Result()
		tokenHash = th
		if err != nil {
			return nil, false, nil
		}
	} else if err != nil {
		return nil, false, err // Redis caído → failover.
	}
	var cr plessCachedRecord
	if jerr := json.Unmarshal([]byte(raw), &cr); jerr != nil {
		return nil, false, nil
	}
	att, _ := c.client.Get(ctx, plessAttKey(hash)).Int()
	exp := time.Unix(cr.ExpUnix, 0).UTC()
	otpHash := cr.OTPHash
	if hash != tokenHash {
		otpHash = hash
	}
	return &auth.PasswordlessRecord{
		UserID: cr.UserID, TokenHash: tokenHash, OTPHash: otpHash,
		ExpiresAt: exp, Attempts: att, Ctx: cr.Ctx,
	}, true, nil
}

// Invalidate borra t/o/active/att (Lua atómico, best-effort).
func (c *PasswordlessCache) Invalidate(ctx context.Context, rec *auth.PasswordlessRecord) {
	if c.client == nil || rec == nil {
		return
	}
	script := redis.NewScript(`
		redis.call('DEL', KEYS[1])
		redis.call('DEL', KEYS[2])
		redis.call('DEL', KEYS[3])
		redis.call('DEL', KEYS[4])
		redis.call('DEL', KEYS[5])
		return 1`)
	_ = script.Run(ctx, c.client,
		[]string{plessTKey(rec.TokenHash), plessOKey(rec.OTPHash), plessActiveKey(rec.UserID), plessAttKey(rec.TokenHash), plessAttKey(rec.OTPHash)}).Err()
}

// IncrAttempts suma intento; retorna conteo (para quemado en >=3).
func (c *PasswordlessCache) IncrAttempts(ctx context.Context, hash string) (int, error) {
	if c.client == nil {
		return 0, redis.ErrClosed
	}
	n, err := c.client.Incr(ctx, plessAttKey(hash)).Result()
	if err != nil {
		return 0, err
	}
	_, _ = c.client.Expire(ctx, plessAttKey(hash), auth.PlessTTL).Result()
	return int(n), nil
}

// QuotaCheck evalúa cooldown 60s + cuota 5/24h por clave (solo lectura).
func (c *PasswordlessCache) QuotaCheck(ctx context.Context, key string) (allowed bool, retryAfter time.Duration, err error) {
	if c.client == nil {
		return false, 0, redis.ErrClosed
	}
	if v, err := c.client.Get(ctx, plessSentKey(key)).Int64(); err == nil {
		if elapsed := time.Since(time.Unix(v, 0)); elapsed < auth.PlessCooldown {
			return false, auth.PlessCooldown - elapsed, nil
		}
	} else if err != redis.Nil {
		return false, 0, err
	}
	n, err := c.client.Get(ctx, plessCountKey(key)).Int()
	if err != nil && err != redis.Nil {
		return false, 0, err
	}
	if n >= auth.PlessMaxDay {
		return false, time.Hour, nil
	}
	return true, 0, nil
}

// NoteSent registra envío (cooldown + cuota). Best-effort post-commit.
func (c *PasswordlessCache) NoteSent(ctx context.Context, key string) {
	if c.client == nil {
		return
	}
	now := time.Now().UTC().Unix()
	pipe := c.client.Pipeline()
	pipe.Set(ctx, plessSentKey(key), now, 24*time.Hour)
	pipe.Incr(ctx, plessCountKey(key))
	pipe.Expire(ctx, plessCountKey(key), 48*time.Hour)
	_, _ = pipe.Exec(ctx)
}
