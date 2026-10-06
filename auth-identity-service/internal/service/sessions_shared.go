package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"auth-identity-service/internal/domain/auth"
)

// Helpers compartidos CU-SES-03 (list + revoke-one): verificación tolerante
// (firma+exp, sin fresh/denylist/valid_after), rate genérico y errores.

// verifySessionBearer valida el Bearer para SES-03 (tolerante a revocado/
// valid_after viejo, exigente con firma+exp+sub). Acepta "Bearer <jwt>".
func verifySessionBearer(verifier auth.LogoutVerifier, bearer string, now time.Time) (auth.AccessClaims, error) {
	if verifier == nil {
		return auth.AccessClaims{}, auth.ErrLogoutUnauthorized
	}
	tok := bearer
	if parts := strings.SplitN(bearer, " ", 2); len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
		tok = strings.TrimSpace(parts[1])
	}
	if tok == "" {
		return auth.AccessClaims{}, auth.ErrLogoutUnauthorized
	}
	claims, err := verifier.Verify(tok)
	if err != nil {
		return auth.AccessClaims{}, err
	}
	if now.Unix() > claims.Exp+int64((auth.ClockSkew/time.Second)) {
		return auth.AccessClaims{}, auth.ErrLogoutUnauthorized
	}
	return claims, nil
}

// checkSessionsRate aplica bucket de usuario (+IP si limits difieren).
// ipLimit<=0 omite el bucket IP (revoke-one es solo-user por spec).
func checkSessionsRate(limiter auth.LogoutLimiter, ctx context.Context, prefix, userID, ip string, userLimit, ipLimit int, window time.Duration) error {
	if limiter == nil {
		return nil
	}
	if userID != "" {
		ok, _, lerr := limiter.Allow(ctx, prefix+"user:"+userID, userLimit, window)
		if lerr == nil && !ok {
			return auth.ErrRateLimited
		}
	}
	if ipLimit > 0 && ip != "" {
		ok, _, lerr := limiter.Allow(ctx, prefix+"ip:"+ip, ipLimit, window)
		if lerr == nil && !ok {
			return auth.ErrRateLimited
		}
	}
	return nil
}

// wrapSessionInfra envuelve fallos de persistencia como 500 base
// (conserva la causa en el mensaje para logs, sin exponerla al cliente).
func wrapSessionInfra(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, auth.ErrSessionInfra) {
		return fmt.Errorf("%s: %w", op, auth.ErrSessionInfra)
	}
	return fmt.Errorf("%s %v: %w", op, err, auth.ErrSessionInfra)
}

func itoaSessions(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
