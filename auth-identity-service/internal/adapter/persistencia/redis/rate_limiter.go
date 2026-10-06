package redis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// RateLimiter sliding-window con Lua. Fail-open local 2x si Redis cae.
type RateLimiter struct {
	client *redis.Client
	strict bool
	mu     sync.Mutex
	local  map[string][]time.Time
}

func NewRateLimiter(client *redis.Client, strict bool) *RateLimiter {
	return &RateLimiter{client: client, strict: strict, local: map[string][]time.Time{}}
}

const luaSlidingWindow = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local count = redis.call('ZCARD', key)
if count >= limit then
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  local retry = window
  if #oldest >= 2 then
    retry = (tonumber(oldest[2]) + window) - now
  end
  return {0, retry}
end
redis.call('ZADD', key, now, now .. ':' .. ARGV[4])
redis.call('PEXPIRE', key, window)
return {1, 0}
`

func (l *RateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, time.Duration, error) {
	nowMs := time.Now().UnixMilli()
	res, err := l.client.Eval(ctx, luaSlidingWindow,
		[]string{key}, nowMs, window.Milliseconds(), limit, nowMs).Slice()
	if err != nil {
		if l.strict {
			return false, window, err
		}
		return l.allowLocal(key, limit*2, window), 0, nil
	}
	if len(res) != 2 {
		return true, 0, nil
	}
	allowedInt, _ := res[0].(int64)
	retryMs, _ := res[1].(int64)
	if allowedInt == 1 {
		return true, 0, nil
	}
	return false, time.Duration(retryMs) * time.Millisecond, nil
}

func (l *RateLimiter) CheckAndIncrement(ctx context.Context, key string, limit int, window time.Duration) (bool, time.Duration, error) {
	return l.Allow(ctx, key, limit, window)
}

func (l *RateLimiter) allowLocal(key string, limit int, window time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-window)
	kept := l.local[key][:0]
	for _, t := range l.local[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	l.local[key] = kept
	if len(kept) >= limit {
		return false
	}
	l.local[key] = append(l.local[key], now)
	return true
}

func IPKey(ip string) string { return "rl:reg:ip:" + ip }

func EmailKey(emailNormalized string) string {
	h := sha256.Sum256([]byte(emailNormalized))
	return "rl:reg:email:" + hex.EncodeToString(h[:])
}

// Bloqueo progresivo CU-REG-03 §4.4: 50x429/15min por IP → bloqueo 15min.
//   announcer:ip:<ip>  contador de 429 EX 900
//   blocked:ip:<ip>    "1" EX 900 (chequeado primero en el middleware)
func announcerKey(ip string) string { return "announcer:ip:" + ip }
func blockedKey(ip string) string   { return "blocked:ip:" + ip }

// IsBlocked indica si la IP está bloqueada progresivamente (+TTL restante).
func (l *RateLimiter) IsBlocked(ctx context.Context, ip string) (bool, time.Duration) {
	if l.client == nil {
		return false, 0
	}
	ttl, err := l.client.TTL(ctx, blockedKey(ip)).Result()
	if err != nil || ttl <= 0 {
		return false, 0
	}
	return true, ttl
}

// NoteRejected cuenta un 429; al llegar al umbral bloquea 15min.
// Retorna blockedNow=true solo en la transición (para métrica ip_blocks_total).
func (l *RateLimiter) NoteRejected(ctx context.Context, ip string, threshold int) (blockedNow bool) {
	if l.client == nil || threshold <= 0 {
		return false
	}
	n, err := l.client.Incr(ctx, announcerKey(ip)).Result()
	if err != nil {
		return false
	}
	_, _ = l.client.Expire(ctx, announcerKey(ip), 15*time.Minute).Result()
	if int(n) == threshold {
		_, _ = l.client.Set(ctx, blockedKey(ip), "1", 15*time.Minute).Result()
		return true
	}
	return false
}
