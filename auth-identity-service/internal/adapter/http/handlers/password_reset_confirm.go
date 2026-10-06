package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"auth-identity-service/internal/adapter/http/dto"
	httperrs "auth-identity-service/internal/adapter/http/errors"
	redisadapter "auth-identity-service/internal/adapter/persistencia/redis"
	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/service"
)

// PwdResetConfirmHandler procesa POST /password/reset/confirm y GET form.
// POST: 200 cambio / 400 policy-reused-opaco / 429. GET: 200 form si formato
// OK (nunca consume ni revela validez). Límite 8KB, `no-store` siempre.
func PwdResetConfirmHandler(svc *service.PasswordResetConfirmService, limiter *redisadapter.RateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
			w.Header().Set("X-Request-ID", reqID)
		}
		if r.Method == http.MethodGet {
			// Form: solo formato, sin lookup ni consumo (nunca oráculo).
			tok := r.URL.Query().Get("token")
			if _, err := auth.ParseResetToken(tok); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(dto.NewError("VALIDATION_FAILED", "Datos inválidos.", nil))
				return
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"data":    map[string]any{"status": "reset_form", "message": "Escribe tu nueva contraseña."},
			})
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
		var req dto.PwdResetConfirmRequest
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
		pwdResetConfirmWith(w, r, svc, limiter, req.Token, req.NewPassword, req.NewPasswordConfirm)
	}
}

func pwdResetConfirmWith(w http.ResponseWriter, r *http.Request, svc *service.PasswordResetConfirmService, limiter *redisadapter.RateLimiter, token, newPassword string, confirm *string) {
	// Rate-limit por hash de token 5/min (fast-reject sin tocar DB).
	if limiter != nil {
		sum := sha256.Sum256([]byte(token))
		key := "rl:pwdreset:confirm:tok:" + hex.EncodeToString(sum[:])
		if ok, retry, err := limiter.Allow(r.Context(), key, 5, time.Minute); err == nil && !ok {
			rateLimited(w, retry)
			return
		}
	}
	in := service.PwdResetConfirmInput{
		Token: token, NewPassword: newPassword,
		RequestID: r.Header.Get("X-Request-ID"),
		IP:        clientIP(r), UserAgent: r.UserAgent(),
	}
	if confirm != nil {
		in.Confirm = *confirm
		in.HasConfirm = true
	}
	out, err := svc.Execute(r.Context(), in)
	if err != nil {
		var ve *service.ValidationError
		if errors.As(err, &ve) {
			details := make([]dto.ErrorDetail, 0, len(ve.Fields))
			for _, f := range ve.Fields {
				details = append(details, dto.ErrorDetail{Field: f.Field, Reason: f.Reason})
			}
			code := "VALIDATION_FAILED"
			if len(ve.Fields) == 1 && ve.Fields[0].Field == "new_password" &&
				ve.Fields[0].Reason != "REQUIRED" && ve.Fields[0].Reason != "INVALID_FORMAT" && ve.Fields[0].Reason != "MISMATCH" {
				code = "PASSWORD_POLICY_FAILED"
			}
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(dto.NewError(code, "Datos inválidos.", details))
			return
		}
		status, code := httperrs.MapDomainError(err)
		switch status {
		case http.StatusTooManyRequests:
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(dto.NewError(code, "Demasiadas solicitudes.", nil))
			return
		case http.StatusBadRequest:
			if code == "PASSWORD_REUSED" {
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(dto.NewPasswordReused())
				return
			}
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(dto.NewPwdResetInvalidOrExpired())
			return
		default:
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(dto.NewError("INTERNAL_ERROR", "No pudimos procesar tu solicitud.", nil))
			return
		}
	}
	_ = out
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(dto.NewPasswordChanged())
}
