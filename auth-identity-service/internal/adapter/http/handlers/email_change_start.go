package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"auth-identity-service/internal/adapter/http/dto"
	"auth-identity-service/internal/adapter/http/middleware"
	redisadapter "auth-identity-service/internal/adapter/persistencia/redis"
	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/user"
	"auth-identity-service/internal/service"
)

// EmailChangeStartHandler procesa POST /email/change/start (con Bearer).
// 202 creado / 400 forma-igual / 401 Step-Up / 409 tomado / 429.
// Límite 2KB, `no-store` siempre.
func EmailChangeStartHandler(svc *service.EmailChangeStartService, limiter *redisadapter.RateLimiter) http.HandlerFunc {
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
		r.Body = http.MaxBytesReader(w, r.Body, 2<<10)
		if r.ContentLength > 2<<10 {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			_ = json.NewEncoder(w).Encode(dto.NewError("PAYLOAD_TOO_LARGE", "Cuerpo demasiado grande.", nil))
			return
		}
		var req dto.EmailChangeStartRequest
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
		// Rate-limit por usuario 3/hora (autenticado: sin oráculo).
		if limiter != nil {
			if allow, retry, lerr := limiter.Allow(r.Context(),
				"rl:emailchange:user:"+uid, 3, time.Hour); lerr == nil && !allow {
				rateLimited(w, retry)
				return
			}
		}
		out, err := svc.Execute(r.Context(), service.EmailChangeStartInput{
			User: service.AuthUser{ID: uid, AuthTime: authTime},
			StepUpToken: strings.TrimSpace(r.Header.Get("X-Step-Up-Token")),
			NewEmailRaw: req.NewEmail, RequestID: r.Header.Get("X-Request-ID"),
		})
		if err != nil {
			writeEmailChangeStartError(w, err)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(dto.NewEmailChangeSent(out.Masked))
	}
}

func writeEmailChangeStartError(w http.ResponseWriter, err error) {
	var ve *service.ValidationError
	if errors.As(err, &ve) {
		for _, f := range ve.Fields {
			if f.Field == "new_email" && f.Reason == "SAME_EMAIL" {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(dto.NewSameEmail())
				return
			}
		}
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(dto.NewError("VALIDATION_FAILED", "Datos inválidos.", nil))
		return
	}
	var throt *service.ThrottledError
	if errors.As(err, &throt) {
		secs := int(throt.RetryAfter.Seconds()) + 1
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(dto.NewEmailSendThrottled())
		return
	}
	switch {
	case errors.Is(err, user.ErrEmailAlreadyInUse):
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(dto.NewEmailTaken())
	case errors.Is(err, auth.ErrStepUpRequired),
		errors.Is(err, auth.ErrStepUpInvalid),
		errors.Is(err, auth.ErrStepUpReused):
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(dto.NewError("STEP_UP_REQUIRED", "Confirma tu identidad.", nil))
	case errors.Is(err, auth.ErrAccountUnavailable):
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(dto.NewError("UNAUTHORIZED", "Autenticación requerida.", nil))
	default:
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(dto.NewError("INTERNAL_ERROR", "No pudimos procesar tu solicitud.", nil))
	}
}
