package redis

import (
	"context"
	"strconv"
	"time"

	"auth-identity-service/internal/domain/auth"

	"github.com/redis/go-redis/v9"
)

// Claves CU-AUTH-01 (nunca email plano; cuenta por sha256):
//
//	login:ip:<ip>            sliding 10/min
//	login:account:<sha256>   sliding 5/min
//	fails:<key>              INCR EX 900 (key = user_id o acct:<sha256>)
//	lock:<key>               {until} EX variable (15/30/60min exponencial)
//	lock_count:<key>         reincidencias (para exponencial)
//	notify:lock:<key>        NX EX 3600 (email aviso 1/h)
func loginIPKey(ip string) string     { return "login:ip:" + ip }
func loginAcctKey(h string) string    { return "login:account:" + h }
func failsKey(key string) string      { return "fails:" + key }
func lockKey(key string) string       { return "lock:" + key }
func lockCountKey(key string) string  { return "lock_count:" + key }
func notifyLockKey(key string) string { return "notify:lock:" + key }

// LoginTracker implementa auth.AttemptTracker con fail-open local.
type LoginTracker struct {
	limiter *RateLimiter
}

func NewLoginTracker(limiter *RateLimiter) *LoginTracker {
	return &LoginTracker{limiter: limiter}
}

func (t *LoginTracker) client() *redis.Client { return t.limiter.client }

// CheckLimits ip 10/min + cuenta 5/min (fast-reject, sin DB/hash).
func (t *LoginTracker) CheckLimits(ctx context.Context, ip, acctHash string) error {
	if t.client() == nil {
		return nil
	}
	if ok, _, err := t.limiter.Allow(ctx, loginIPKey(ip), auth.LoginIPLimit, auth.LoginIPWindow); err == nil && !ok {
		return auth.ErrRateLimited
	}
	if ok, _, err := t.limiter.Allow(ctx, loginAcctKey(acctHash), auth.LoginAcctLimit, auth.LoginAcctWindow); err == nil && !ok {
		return auth.ErrRateLimited
	}
	return nil
}

// IsLocked indica bloqueo vigente (fail-open false si Redis cae).
func (t *LoginTracker) IsLocked(ctx context.Context, key string) (bool, error) {
	if t.client() == nil {
		return false, nil
	}
	v, err := t.client().Get(ctx, lockKey(key)).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, nil
	}
	until, perr := strconv.ParseInt(v, 10, 64)
	if perr != nil {
		return false, nil
	}
	return time.Now().Unix() < until, nil
}

// RecordFail suma fallo; al umbral bloquea exponencial.
// sendEmail=true solo en el 1º bloqueo de la hora (throttle).
func (t *LoginTracker) RecordFail(ctx context.Context, key string) (lockedNow, sendEmail bool, err error) {
	if t.client() == nil {
		return false, false, nil
	}
	n, err := t.client().Incr(ctx, failsKey(key)).Result()
	if err != nil {
		return false, false, nil
	}
	_, _ = t.client().Expire(ctx, failsKey(key), auth.LoginFailWindow).Result()
	if int(n) < auth.LoginMaxFails {
		return false, false, nil
	}
	// Umbral: calcula reincidencia y bloquea.
	c, _ := t.client().Incr(ctx, lockCountKey(key)).Result()
	_, _ = t.client().Expire(ctx, lockCountKey(key), 24*time.Hour).Result()
	dur := auth.LockDuration(int(c))
	until := time.Now().Add(dur).Unix()
	_ = t.client().Set(ctx, lockKey(key), until, dur).Err()
	_, _ = t.client().Del(ctx, failsKey(key)).Result()
	// Email 1/hora (solo el primer bloqueo de la ventana avisa).
	sent, _ := t.client().SetNX(ctx, notifyLockKey(key), "1", time.Hour).Result()
	return true, sent, nil
}

// ResetOnSuccess limpia fails/lock tras éxito.
func (t *LoginTracker) ResetOnSuccess(ctx context.Context, key string) error {
	if t.client() == nil {
		return nil
	}
	_, _ = t.client().Del(ctx, failsKey(key), lockKey(key)).Result()
	return nil
}

var _ auth.AttemptTracker = (*LoginTracker)(nil)
