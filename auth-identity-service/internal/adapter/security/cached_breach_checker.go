package security

import (
	"context"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/hex"
	"strings"
	"time"

	"auth-identity-service/internal/domain/auth"

	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/singleflight"
)

// HIBPCacheTTL ventana fija de frescura por prefijo (F-19 CU-REG-01).
// El corpus HIBP solo crece: un TTL largo alarga la ventana ciega ante
// brechas nuevas; 1h equilibra latencia y staleness. Sin sliding.
const HIBPCacheTTL = time.Hour

// hibpCacheKey bucket k-anonymity: el prefijo identifica ~500k passwords,
// no revela nada del password completo.
func hibpCacheKey(prefix string) string { return "hibp:p:" + prefix }

// CacheMetrics telemetría del decorador (nil-safe). Implementada en
// adapter/http para no acoplar seguridad a Prometheus.
type CacheMetrics interface {
	IncHibpCache(result string) // hit|miss|redis_error
}

// CachedBreachChecker decora auth.BreachChecker con caché Redis por
// prefijo SHA-1 (F-19 CU-REG-01). Redis caído o cliente nil → comporta
// como el checker interno (misma seguridad, más latencia). Error del
// checker interno → se propaga (el servicio aplica fallback local-deny).
type CachedBreachChecker struct {
	inner   auth.BreachChecker
	rdb     *redis.Client
	metrics CacheMetrics
	flight  singleflight.Group
}

// NewCachedBreachChecker envuelve inner; rdb o metrics nil = degradación
// parcial (sin caché o sin telemetría), nunca error.
func NewCachedBreachChecker(inner auth.BreachChecker, rdb *redis.Client, metrics CacheMetrics) *CachedBreachChecker {
	return &CachedBreachChecker{inner: inner, rdb: rdb, metrics: metrics}
}

func (c *CachedBreachChecker) hitResult(hit bool) {
	if c.metrics == nil {
		return
	}
	if hit {
		c.metrics.IncHibpCache("hit")
		return
	}
	c.metrics.IncHibpCache("miss")
}

// IsCompromised implementa auth.BreachChecker.
func (c *CachedBreachChecker) IsCompromised(ctx context.Context, password string) (bool, error) {
	sum := sha1.Sum([]byte(password))
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := full[:5], full[5:]

	// Sin Redis: passthrough (tests sin infra, degradación).
	if c.rdb == nil {
		return c.inner.IsCompromised(ctx, password)
	}
	if raw, ok := c.get(ctx, prefix); ok {
		c.hitResult(true)
		return matchSuffix(raw, suffix), nil
	}
	c.hitResult(false)
	// Colapsa misses concurrentes del mismo prefijo (thundering herd).
	v, err, _ := c.flight.Do(prefix, func() (any, error) {
		rf, ok := c.inner.(rangeFetcher)
		if !ok {
			// Inner sin rango crudo (mock): veredicto sin guardar.
			return c.inner.IsCompromised(ctx, password)
		}
		raw, ferr := rf.FetchRange(ctx, prefix)
		if ferr != nil {
			return false, ferr
		}
		c.set(ctx, prefix, raw)
		return matchSuffix(raw, suffix), nil
	})
	if err != nil {
		return false, err
	}
	return v.(bool), nil
}

// get lee el bucket crudo; ok=false ante cualquier fallo (miss).
func (c *CachedBreachChecker) get(ctx context.Context, prefix string) (string, bool) {
	raw, err := c.rdb.Get(ctx, hibpCacheKey(prefix)).Result()
	if err != nil {
		if c.metrics != nil {
			c.metrics.IncHibpCache("redis_error")
		}
		return "", false
	}
	return raw, true
}

// set guarda con TTL fija (sin sliding). Error → se ignora (miss futuro).
func (c *CachedBreachChecker) set(ctx context.Context, prefix, raw string) {
	if err := c.rdb.Set(ctx, hibpCacheKey(prefix), raw, HIBPCacheTTL).Err(); err != nil {
		if c.metrics != nil {
			c.metrics.IncHibpCache("redis_error")
		}
	}
}

// rangeFetcher expone el cuerpo crudo del rango (una llamada HIBP).
// Lo implementa *HIBPBreachChecker; otros checkers (mocks) no lo
// tienen y el decorador degrada a veredicto sin guardar.
type rangeFetcher interface {
	FetchRange(ctx context.Context, prefix string) (string, error)
}

// matchSuffix compara en tiempo constante (sufijos de 35 hex).
func matchSuffix(raw, suffix string) bool {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if idx := strings.Index(line, ":"); idx > 0 {
			cand := strings.ToUpper(strings.TrimSpace(line[:idx]))
			if len(cand) == len(suffix) && subtle.ConstantTimeCompare([]byte(cand), []byte(suffix)) == 1 {
				return true
			}
		}
	}
	return false
}
