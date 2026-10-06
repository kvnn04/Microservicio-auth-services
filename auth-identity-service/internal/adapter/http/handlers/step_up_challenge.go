package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"auth-identity-service/internal/adapter/http/dto"
	"auth-identity-service/internal/adapter/http/middleware"
	redisadapter "auth-identity-service/internal/adapter/persistencia/redis"
	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/service"
)

// StepUpChallengeHandler procesa POST /step-up/challenge (con Bearer).
// 200 token scopeado / 400 scope/forma / 401 opaco/relogin / 429 / 500.
// Límite 4KB, `no-store` siempre.
func StepUpChallengeHandler(svc *service.StepUpService, limiter *redisadapter.RateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
			w.Header().Set("X-Request-ID", reqID)
		}
		au, ok := stepUpAuthed(r)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(dto.NewError("UNAUTHORIZED", "Autenticación requerida.", nil))
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(dto.NewError("UNSUPPORTED_MEDIA_TYPE",
				"Content-Type debe ser application/json.", nil))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		var req dto.StepUpChallengeRequest
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) || strings.Contains(err.Error(), "request body too large") {
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				_ = json.NewEncoder(w).Encode(dto.NewError("PAYLOAD_TOO_LARGE", "Cuerpo demasiado grande.", nil))
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(dto.NewError("INVALID_JSON", "Datos inválidos.", nil))
			return
		}
		// Rate por usuario 10/min (el de IP 30/min lo pone el middleware en main).
		if limiter != nil {
			if allow, retry, lerr := limiter.Allow(r.Context(),
				"rl:step-up:challenge:"+au.ID, 10, time.Minute); lerr == nil && !allow {
				rateLimited(w, retry)
				return
			}
		}
		var password, code string
		if req.Password != nil {
			password = *req.Password
		}
		if req.Code != nil {
			code = strings.TrimSpace(*req.Code)
		}
		out, err := svc.Challenge(r.Context(), service.StepUpChallengeInput{
			User:  service.AuthUser{ID: au.ID, AuthTime: au.AuthTime},
			Scope: req.Scope, Password: password, Code: code,
			RequestID: r.Header.Get("X-Request-ID"),
		})
		if err != nil {
			writeStepUpError(w, err)
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(dto.NewStepUpChallenge(out.Token, out.Scope, out.ExpiresIn))
	}
}

// stepUpAuthed extrae identidad del middleware RequireAuth.
func stepUpAuthed(r *http.Request) (service.AuthUser, bool) {
	uid, at, ok := middleware.AuthUserFromContext(r.Context())
	if !ok {
		return service.AuthUser{}, false
	}
	return service.AuthUser{ID: uid, AuthTime: at}, true
}

func writeStepUpError(w http.ResponseWriter, err error) {
	var ve *service.ValidationError
	if errors.As(err, &ve) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(dto.NewError("VALIDATION_FAILED", "Datos inválidos.", nil))
		return
	}
	switch {
	case errors.Is(err, auth.ErrUnknownScope):
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(dto.NewError("UNKNOWN_SCOPE", "Operación no reconocida.", nil))
	case errors.Is(err, auth.ErrStepUpRelogin):
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(dto.NewStepUpRelogin())
	case errors.Is(err, auth.ErrStepUpInvalid):
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(dto.NewInvalidStepUp())
	case errors.Is(err, auth.ErrAccountUnavailable):
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(dto.NewError("ACCOUNT_UNAVAILABLE", "Cuenta no disponible.", nil))
	case errors.Is(err, auth.ErrStepUpUnavailable):
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(dto.NewStepUpUnavailable())
	default:
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(dto.NewError("INTERNAL_ERROR", "No pudimos procesar tu solicitud.", nil))
	}
}
