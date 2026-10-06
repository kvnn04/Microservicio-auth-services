package redis

import (
	"context"
	"encoding/json"
	"time"

	"auth-identity-service/internal/domain/auth"

	"github.com/redis/go-redis/v9"
)

// Claves efímeras CU-REG-02 (nunca PII: solo hashes SHA-256 hex y UUIDs).
//   verify:t:<token_hash>          JSON {user_id, otp_hash, exp} EX 900 NX
//   verify:o:<otp_hash>            <token_hash> EX 900 NX
//   verify:active:<user_id>        <token_hash> EX 900 (sobrescribe)
//   verify:att:<hash>              contador intentos EX 900
//   verify:sent:<user_id>          unix envío EX 86400 (cooldown 60s)
//   verify:resends:<uid>:<yyyy-mm-dd> contador cuota EX 172800
func tKey(h string) string      { return "verify:t:" + h }
func oKey(h string) string      { return "verify:o:" + h }
func activeKey(u string) string { return "verify:active:" + u }
func attKey(h string) string    { return "verify:att:" + h }
func sentKey(u string) string   { return "verify:sent:" + u }

func resendsKey(u string) string {
	return "verify:resends:" + u + ":" + time.Now().UTC().Format("2006-01-02")
}

type cachedRecord struct {
	UserID  string `json:"user_id"`
	OTPHash string `json:"otp_hash"`
	ExpUnix int64  `json:"exp"`
}

// VerificationCache es la verdad rápida (Redis) del puerto VerificationStore.
// Todos los métodos retornan redis.Nil/error si Redis cae para failover a Postgres.
type VerificationCache struct {
	client *redis.Client
}

func NewVerificationCache(client *redis.Client) *VerificationCache {
	return &VerificationCache{client: client}
}

func (c *VerificationCache) Put(ctx context.Context, rec *auth.VerificationRecord) error {
	if c.client == nil {
		return redis.ErrClosed
	}
	ttl := time.Until(rec.ExpiresAt)
	if ttl <= 0 {
		return nil
	}
	if ttl > 15*time.Minute {
		ttl = 15 * time.Minute
	}
	body, _ := json.Marshal(cachedRecord{UserID: rec.UserID, OTPHash: rec.OTPHash, ExpUnix: rec.ExpiresAt.Unix()})
	pipe := c.client.Pipeline()
	pipe.SetNX(ctx, tKey(rec.TokenHash), string(body), ttl)
	if rec.OTPHash != "" {
		pipe.SetNX(ctx, oKey(rec.OTPHash), rec.TokenHash, ttl)
	}
	pipe.Set(ctx, activeKey(rec.UserID), rec.TokenHash, ttl)
	_, err := pipe.Exec(ctx)
	return err
}

// Get busca por hash (token u OTP). hit=false si miss (fallback Postgres).
func (c *VerificationCache) Get(ctx context.Context, hash string) (rec *auth.VerificationRecord, hit bool, err error) {
	if c.client == nil {
		return nil, false, redis.ErrClosed
	}
	raw, err := c.client.Get(ctx, tKey(hash)).Result()
	tokenHash := hash
	if err == redis.Nil {
		// ¿Es OTP? o:<otp> → token_hash.
		th, oerr := c.client.Get(ctx, oKey(hash)).Result()
		if oerr == redis.Nil {
			return nil, false, nil // miss → fallback Postgres.
		}
		if oerr != nil {
			return nil, false, oerr // Redis caído → failover.
		}
		raw, err = c.client.Get(ctx, tKey(th)).Result()
		tokenHash = th
		if err != nil {
			return nil, false, nil
		}
	} else if err != nil {
		return nil, false, err // Redis caído → failover.
	}
	var cr cachedRecord
	if jerr := json.Unmarshal([]byte(raw), &cr); jerr != nil {
		return nil, false, nil
	}
	att, _ := c.client.Get(ctx, attKey(hash)).Int()
	exp := time.Unix(cr.ExpUnix, 0).UTC()
	return &auth.VerificationRecord{
		UserID: cr.UserID, TokenHash: tokenHash, OTPHash: cr.OTPHash,
		ExpiresAt: exp, Attempts: att,
	}, true, nil
}

// Invalidate borra t/o/active/att (Lua atómico, best-effort).
func (c *VerificationCache) Invalidate(ctx context.Context, rec *auth.VerificationRecord) {
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
		[]string{tKey(rec.TokenHash), oKey(rec.OTPHash), activeKey(rec.UserID), attKey(rec.TokenHash), attKey(rec.OTPHash)}).Err()
}

// IncrAttempts suma intento; retorna conteo (para quemado en >=3).
func (c *VerificationCache) IncrAttempts(ctx context.Context, hash string) (int, error) {
	if c.client == nil {
		return 0, redis.ErrClosed
	}
	n, err := c.client.Incr(ctx, attKey(hash)).Result()
	if err != nil {
		return 0, err
	}
	_, _ = c.client.Expire(ctx, attKey(hash), 15*time.Minute).Result()
	return int(n), nil
}

// QuotaCheck evalúa cooldown 60s + cuota 5/24h (solo lectura).
func (c *VerificationCache) QuotaCheck(ctx context.Context, userID string) (allowed bool, retryAfter time.Duration, err error) {
	if c.client == nil {
		return false, 0, redis.ErrClosed
	}
	if v, err := c.client.Get(ctx, sentKey(userID)).Int64(); err == nil {
		if elapsed := time.Since(time.Unix(v, 0)); elapsed < auth.ResendCooldown {
			return false, auth.ResendCooldown - elapsed, nil
		}
	} else if err != redis.Nil {
		return false, 0, err
	}
	n, err := c.client.Get(ctx, resendsKey(userID)).Int()
	if err != nil && err != redis.Nil {
		return false, 0, err
	}
	if n >= auth.ResendQuota24h {
		return false, time.Hour, nil
	}
	return true, 0, nil
}

// NoteSent registra envío (cooldown + cuota). Best-effort post-commit.
func (c *VerificationCache) NoteSent(ctx context.Context, userID string) {
	if c.client == nil {
		return
	}
	now := time.Now().UTC().Unix()
	pipe := c.client.Pipeline()
	pipe.Set(ctx, sentKey(userID), now, 24*time.Hour)
	pipe.Incr(ctx, resendsKey(userID))
	pipe.Expire(ctx, resendsKey(userID), 48*time.Hour)
	_, _ = pipe.Exec(ctx)
}
