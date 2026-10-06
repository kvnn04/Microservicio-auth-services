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

// ChangePasswordHandler procesa POST /password/change (con Bearer).
// 200 cambio (pares revocados, actual intacta) / 400 policy-reused-history /
// 401 current-stepup / 429. Límite 8KB, `no-store` siempre.
func ChangePasswordHandler(svc *service.ChangePasswordService, limiter *redisadapter.RateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
			w.Header().Set("X-Request-ID", reqID)
		}
		uid, authTime, ok := middleware.AuthUserFromContext(r.Context())
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
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		if r.ContentLength > 8<<10 {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			_ = json.NewEncoder(w).Encode(dto.NewError("PAYLOAD_TOO_LARGE", "Cuerpo demasiado grande.", nil))
			return
		}
		var req dto.ChangePasswordRequest
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
		// Rate-limit por usuario 5/hora (sin distinguir causa).
		if limiter != nil {
			if allow, retry, lerr := limiter.Allow(r.Context(),
				"rl:pwdchange:user:"+uid, 5, time.Hour); lerr == nil && !allow {
				rateLimited(w, retry)
				return
			}
		}
		in := service.ChangePasswordInput{
			User:        service.AuthUser{ID: uid, AuthTime: authTime},
			SID:         middleware.AuthSIDFromContext(r.Context()),
			NewPassword: req.NewPassword,
			StepUpToken: strings.TrimSpace(r.Header.Get("X-Step-Up-Token")),
			RequestID:   r.Header.Get("X-Request-ID"),
		}
		if req.CurrentPassword != nil {
			in.Current = *req.CurrentPassword
			in.HasCurrent = true
		}
		out, err := svc.Execute(r.Context(), in)
		if err != nil {
			writeChangeError(w, err)
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(dto.NewPasswordChangedResult(out.SessionsRevoked))
	}
}

func writeChangeError(w http.ResponseWriter, err error) {
	var ve *service.ValidationError
	if errors.As(err, &ve) {
		for _, f := range ve.Fields {
			switch {
			case f.Field == "current_password" && f.Reason == "MISSING_CURRENT":
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(dto.NewMissingCurrent())
				return
			case f.Field == "current_password" && f.Reason == "UNEXPECTED_CURRENT":
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(dto.NewUnexpectedCurrent())
				return
			case f.Field == "new_password":
				details := make([]dto.ErrorDetail, 0, len(ve.Fields))
				for _, ff := range ve.Fields {
					details = append(details, dto.ErrorDetail{Field: ff.Field, Reason: ff.Reason})
				}
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(dto.NewError("PASSWORD_POLICY_FAILED", "La nueva clave no cumple la política.", details))
				return
			}
		}
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(dto.NewError("VALIDATION_FAILED", "Datos inválidos.", nil))
		return
	}
	switch {
	case errors.Is(err, auth.ErrInvalidCurrent):
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(dto.NewInvalidCurrent())
	case errors.Is(err, auth.ErrPasswordReused):
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(dto.NewPasswordReused())
	case errors.Is(err, auth.ErrPasswordInHistory):
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(dto.NewPasswordInHistory())
	case errors.Is(err, auth.ErrStepUpRequired),
		errors.Is(err, auth.ErrStepUpInvalid):
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(dto.NewError("STEP_UP_REQUIRED", "Confirma tu identidad.", nil))
	case errors.Is(err, auth.ErrStepUpReused):
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(dto.NewStepUpReused())
	case errors.Is(err, auth.ErrStepUpUnavailable):
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(dto.NewStepUpUnavailable())
	case errors.Is(err, auth.ErrAccountUnavailable):
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(dto.NewError("UNAUTHORIZED", "Autenticación requerida.", nil))
	default:
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(dto.NewError("INTERNAL_ERROR", "No pudimos procesar tu solicitud.", nil))
	}
}
