package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"auth-identity-service/internal/adapter/security"
)

type authCtxKey string

const (
	authUserKey      authCtxKey = "auth_user_id"
	authTimeKey      authCtxKey = "auth_time"
	maxStepUpAgeKey  authCtxKey = "step_up_max_age"
)

// RequireAuth valida Bearer o cookie access_token (transición: acepta ambas;
// CU-AUTH-04 emite Access en body → Bearer, nunca en cookie en prod).
// Rechaza pre-tokens MFA (aud=mfa-challenge) en APIs negocio. Sin token → 401.
func RequireAuth(issuer interface {
	VerifyBusiness(string) (*security.VerifiedSession, error)
}) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := bearerToken(r)
			if token == "" {
				unauthorized(w)
				return
			}
			sess, err := issuer.VerifyBusiness(token)
			if err != nil {
				unauthorized(w)
				return
			}
			ctx := context.WithValue(r.Context(), authUserKey, sess.UserID)
			ctx = context.WithValue(ctx, authTimeKey, sess.AuthTime)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireFreshAuth exige auth_time ≤ maxAge o 401 STEP_UP_REQUIRED + meta.
// No aplica a lectura (GET linked).
func RequireFreshAuth(maxAge time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			at, _ := r.Context().Value(authTimeKey).(time.Time)
			if at.IsZero() || time.Since(at.UTC()) > maxAge {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success": false,
					"error":   map[string]any{"code": "STEP_UP_REQUIRED", "message": "Confirma tu identidad de nuevo.", "details": []any{}},
					"meta":    map[string]any{"max_age": int(maxAge.Seconds())},
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func bearerToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if parts := strings.SplitN(h, " ", 2); len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
			return strings.TrimSpace(parts[1])
		}
	}
	if c, err := r.Cookie("access_token"); err == nil {
		return c.Value
	}
	return ""
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": false,
		"error":   map[string]any{"code": "UNAUTHORIZED", "message": "Autenticación requerida.", "details": []any{}},
	})
}

// AuthUserFromContext recupera identidad del Bearer (para handlers → servicio).
func AuthUserFromContext(ctx context.Context) (userID string, authTime time.Time, ok bool) {
	uid, _ := ctx.Value(authUserKey).(string)
	at, _ := ctx.Value(authTimeKey).(time.Time)
	if uid == "" {
		return "", time.Time{}, false
	}
	return uid, at, true
}
