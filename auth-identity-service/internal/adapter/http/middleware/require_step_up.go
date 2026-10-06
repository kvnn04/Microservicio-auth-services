package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/service"
)

// StepUpChecker verifica fast-pass o token para un scope (lo implementa
// *service.StepUpService; interfaz para tests sin Redis/DB).
type StepUpChecker interface {
	Check(ctx context.Context, callerUserID string, bearerAuthTime time.Time, scope auth.StepUpScope, token string) (string, error)
}

// RequireStepUp exige revalidación fresca para una op crítica (CU-AUTH-06).
// Acepta fast-pass (`auth_time` ≤5min, verificable offline) O `X-Step-Up-Token`
// scopeado de un uso. Debe correr DESPUÉS de RequireAuth (necesita identidad).
// Con enforceToken=true el fast-pass no basta (modo estricto futuro;
// default false = compatibilidad fast-pass O token).
func RequireStepUp(scope auth.StepUpScope, checker StepUpChecker, enforceToken bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			uid, authTime, ok := AuthUserFromContext(r.Context())
			if !ok {
				unauthorized(w)
				return
			}
			token := r.Header.Get("X-Step-Up-Token")
			mode, err := checker.Check(r.Context(), uid, authTime, scope, token)
			if err == nil {
				if enforceToken && mode == service.StepUpFastPass {
					stepUpRequired(w, scope)
					return
				}
				next.ServeHTTP(w, r.WithContext(service.StepUpContext(r.Context(), mode, scope)))
				return
			}
			switch {
			case errors.Is(err, auth.ErrStepUpRequired):
				stepUpRequired(w, scope)
			case errors.Is(err, auth.ErrStepUpReused):
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success": false,
					"error":   map[string]any{"code": "STEP_UP_REUSED", "message": "Ese comprobante ya fue usado. Solicita uno nuevo.", "details": []any{}},
				})
			case errors.Is(err, auth.ErrStepUpUnavailable):
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success": false,
					"error":   map[string]any{"code": "STEP_UP_UNAVAILABLE", "message": "No pudimos confirmarte ahora. Intenta de nuevo.", "details": []any{}},
				})
			default:
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success": false,
					"error":   map[string]any{"code": "INVALID_STEP_UP", "message": "No pudimos confirmarte.", "details": []any{}},
				})
			}
		})
	}
}

func stepUpRequired(w http.ResponseWriter, scope auth.StepUpScope) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": false,
		"error":   map[string]any{"code": "STEP_UP_REQUIRED", "message": "Confirma tu identidad para continuar.", "details": []any{}},
		"meta": map[string]any{
			"scope": string(scope), "max_age": 300,
			"challenge": "POST /api/v1/auth/step-up/challenge",
		},
	})
}
