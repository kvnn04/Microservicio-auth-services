package auth

import (
	"context"
	"time"
)

// CacheRepository puerto para rate-limit/sesiones (Redis). Sin PII en keys.
type CacheRepository interface {
	CheckAndIncrement(ctx context.Context, key string, limit int, window time.Duration) (allowed bool, retryAfter time.Duration, err error)
}

// TokenPair par de sesión (CU-AUTH-04). En CU-REG-01 no se emite (RN-01).
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}
