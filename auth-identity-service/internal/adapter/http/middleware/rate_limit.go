package middleware

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	redisadapter "auth-identity-service/internal/adapter/persistencia/redis"
)

// RateLimit 10 req/min/IP. Fast-reject sin cripto pesada. Fail-open salvo strict.
func RateLimit(limiter *redisadapter.RateLimiter) func(http.Handler) http.Handler {
	return RateLimitKey(limiter, func(r *http.Request) string {
		return redisadapter.IPKey(clientIP(r))
	}, 10, time.Minute)
}

// RateLimitKey genérico por clave/límite/ventana (verify:ip, resend:ip, ...).
func RateLimitKey(limiter *redisadapter.RateLimiter, keyFn func(*http.Request) string, limit int, window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			allowed, retry, err := limiter.Allow(r.Context(), keyFn(r), limit, window)
			if err == nil && !allowed {
				secs := int(retry.Seconds()) + 1
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", strconv.Itoa(secs))
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"success":false,"error":{"code":"RATE_LIMITED","message":"Demasiadas solicitudes. Intenta de nuevo en unos segundos.","details":[]}}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
func clientIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		if i := strings.Index(v, ","); i >= 0 {
			return strings.TrimSpace(v[:i])
		}
		return strings.TrimSpace(v)
	}
	return r.RemoteAddr
}

// BlockReporter cuenta bloqueos progresivos (ip_blocks_total).
type BlockReporter interface{ IncIPBlocked() }

// RateLimitProgressive añade bloqueo progresivo CU-REG-03 §4.4 sobre RateLimitKey:
// chequea `blocked:ip` primero (429 largo) y cuenta cada 429 hacia el umbral.
func RateLimitProgressive(limiter *redisadapter.RateLimiter, keyFn func(*http.Request) string, limit int, window time.Duration, threshold int, blocks BlockReporter) func(http.Handler) http.Handler {
	base := RateLimitKey(limiter, keyFn, limit, window)
	return func(next http.Handler) http.Handler {
		inner := base(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
		}))
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			if blocked, ttl := limiter.IsBlocked(r.Context(), ip); blocked {
				secs := int(ttl.Seconds()) + 1
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", strconv.Itoa(secs))
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"success":false,"error":{"code":"RATE_LIMITED","message":"Demasiadas solicitudes. Intenta de nuevo en unos segundos.","details":[]}}`))
				return
			}
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			inner.ServeHTTP(rec, r)
			if rec.status == http.StatusTooManyRequests && threshold > 0 {
				if limiter.NoteRejected(r.Context(), ip, threshold) && blocks != nil {
					blocks.IncIPBlocked()
				}
			}
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
