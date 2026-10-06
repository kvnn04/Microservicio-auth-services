package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"auth-identity-service/internal/domain/auth"

	"github.com/google/uuid"
)

// SessionTouch refresca last_seen best-effort (supuesto Q5 confirmado).
// Lee el sid del Bearer (o de `X-Session-Touch` si trae UUID válido) y, tras
// verificación tolerante, dispara Touch async con debounce 5min/sid.
// Jamás falla ni retrasa la respuesta: sin Bearer/verificación → no-op;
// el store traga errores (WARN interno) porque PG es la verdad.
// Se monta sobre rutas autenticadas que ya verifican (el doble-verify
// Ed25519 cuesta µs y mantiene el middleware desacoplado del handler).
func SessionTouch(verifier auth.LogoutVerifier, toucher auth.SessionToucher) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if toucher != nil {
				touchAsync(verifier, toucher, r)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func touchAsync(verifier auth.LogoutVerifier, toucher auth.SessionToucher, r *http.Request) {
	if verifier == nil {
		return
	}
	tok := ""
	if h := r.Header.Get("Authorization"); h != "" {
		if parts := strings.SplitN(h, " ", 2); len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
			tok = strings.TrimSpace(parts[1])
		}
	}
	if tok == "" {
		return
	}
	claims, err := verifier.Verify(tok)
	if err != nil || claims.Sub == "" || claims.SID == "" {
		return
	}
	sid := claims.SID
	if hdr := strings.TrimSpace(r.Header.Get("X-Session-Touch")); hdr != "" {
		if _, perr := uuid.Parse(hdr); perr == nil {
			sid = hdr // el store lo acota a user_id==sub (no-op ajeno)
		}
	}
	// Contexto desacoplado: el touch sobrevive al fin del request (≤3s).
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 3*time.Second)
	go func() {
		defer cancel()
		_ = toucher.Touch(ctx, claims.Sub, sid, time.Now().UTC())
	}()
}
