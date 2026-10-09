//go:build e2e

package e2e

import (
	"context"
	"time"

	"auth-identity-service/internal/domain/auth"
)

// e2eIssueSessions fake enterprise para E2E (sin PG/Redis de sesiones;
// el foco E2E es flujo federado/MFA, no persistencia de tokens).
type e2eIssueSessions struct{}

func (e2eIssueSessions) Issue(_ context.Context, req auth.SessionRequest) (auth.IssuedPair, error) {
	return auth.IssuedPair{
		AccessJWT: "e2e-at-" + req.UserID, RefreshPlain: "e2e-rt-43ch-test-vector-0000000000000",
		SID: "sid-" + req.UserID, JTI: "jti", Family: "fam", KID: "2026-10-a",
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}, nil
}
