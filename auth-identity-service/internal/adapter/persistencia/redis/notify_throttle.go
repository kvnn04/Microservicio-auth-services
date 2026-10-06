package redis

import (
	"context"
	"time"

	"auth-identity-service/internal/domain/user"

	"github.com/redis/go-redis/v9"
)

// Claves de throttling notify (CU-REG-03 RN-03): 1/hora + 3/día por email_hash.
//   notify:hour:<sha256hex>       SET NX EX 3600 (ventana horaria)
//   notify:day:<sha256hex>:<yyyy-mm-dd>  contador EX 172800 (cuota diaria)
func notifyHourKey(emailHash string) string { return "notify:hour:" + emailHash }

func notifyDayKey(emailHash string) string {
	return "notify:day:" + emailHash + ":" + time.Now().UTC().Format("2006-01-02")
}

// RedisNotifyThrottle implementa user.NotifyThrottle.
// Fail-open: si Redis cae retorna allowed=true + error (el servicio encola
// igual y la métrica de fallback se registra en el caller vía onFallback).
type RedisNotifyThrottle struct {
	client    *redis.Client
	perHour   int
	perDay    int
	onFallback func(string)
}

func NewRedisNotifyThrottle(client *redis.Client, perHour, perDay int, onFallback func(string)) *RedisNotifyThrottle {
	if perHour <= 0 {
		perHour = 1
	}
	if perDay <= 0 {
		perDay = 3
	}
	if onFallback == nil {
		onFallback = func(string) {}
	}
	return &RedisNotifyThrottle{client: client, perHour: perHour, perDay: perDay, onFallback: onFallback}
}

func (t *RedisNotifyThrottle) AllowOwnerNotify(ctx context.Context, emailHash string) (bool, error) {
	if t.client == nil {
		t.onFallback("down")
		return true, nil
	}
	// Ventana horaria (1/hora por defecto): contador con EX 3600.
	nh, err := t.client.Incr(ctx, notifyHourKey(emailHash)).Result()
	if err != nil {
		t.onFallback("down")
		return true, nil
	}
	_, _ = t.client.Expire(ctx, notifyHourKey(emailHash), time.Hour).Result()
	if int(nh) > t.perHour {
		return false, nil
	}
	// Cuota diaria (3/día por defecto).
	n, err := t.client.Incr(ctx, notifyDayKey(emailHash)).Result()
	if err != nil {
		t.onFallback("down")
		return true, nil
	}
	_, _ = t.client.Expire(ctx, notifyDayKey(emailHash), 48*time.Hour).Result()
	if int(n) > t.perDay {
		return false, nil
	}
	return true, nil
}

var _ user.NotifyThrottle = (*RedisNotifyThrottle)(nil)
