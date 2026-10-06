package redis

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// LogoutCache revocación individual CU-SES-01 (T-08).
// Triple-capa cache: DEL sess/fam + SET jti revoked EX=restante.
// Best-effort post-commit: el error NO revierte la Tx PG (el servicio
// lo cuenta como fallback y PG sigue siendo verdad vía revoked_jtis).
type LogoutCache struct {
	client *redis.Client
}

func NewLogoutCache(client *redis.Client) *LogoutCache {
	return &LogoutCache{client: client}
}

// Revoke borra sesión/family y denylistea el jti hasta su exp natural.
// ttl ya viene clamp 1s..15min del dominio (DenylistTTL).
func (c *LogoutCache) Revoke(ctx context.Context, sid, family, jti string, ttl time.Duration) error {
	if c.client == nil {
		return redis.ErrClosed
	}
	if ttl <= 0 {
		ttl = time.Second
	}
	if ttl > 15*time.Minute {
		ttl = 15 * time.Minute
	}
	pipe := c.client.Pipeline()
	if sid != "" {
		pipe.Del(ctx, sessKey(sid))
	}
	if family != "" {
		pipe.Del(ctx, famKey(family))
	}
	if jti != "" {
		pipe.Set(ctx, jtiKey(jti), "revoked", ttl)
	}
	_, err := pipe.Exec(ctx)
	return err
}

// RevokeByHash además limpia el índice inverso del refresh usado.
func (c *LogoutCache) RevokeByHash(ctx context.Context, sid, family, jti, refreshHash string, ttl time.Duration) error {
	if err := c.Revoke(ctx, sid, family, jti, ttl); err != nil {
		return err
	}
	if c.client == nil || refreshHash == "" {
		return nil
	}
	// Best-effort: el hash queda huérfano con TTL, no bloquea.
	_ = c.client.Del(ctx, RefreshByHashKey(refreshHash)).Err()
	return nil
}

// LookupFamilyByHash intenta resolver family sin tocar PG (índice Issue).
// Miss → "" (el Revoker cae a PG, verdad).
func (c *LogoutCache) LookupFamilyByHash(ctx context.Context, refreshHash string) string {
	if c.client == nil || refreshHash == "" {
		return ""
	}
	fam, err := c.client.Get(ctx, RefreshByHashKey(refreshHash)).Result()
	if err != nil {
		return ""
	}
	return fam
}

// DenylistSize aprox para logout_denylist_size_gauge (DBSIZE muestreado).
// Si Redis cae, retorna -1 (el worker la actualiza vía PG COUNT).
func (c *LogoutCache) DenylistSize(ctx context.Context) int64 {
	if c.client == nil {
		return -1
	}
	n, err := c.client.DBSize(ctx).Result()
	if err != nil {
		return -1
	}
	return n
}
