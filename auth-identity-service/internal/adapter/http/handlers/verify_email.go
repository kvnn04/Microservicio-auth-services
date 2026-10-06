package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"auth-identity-service/internal/adapter/http/dto"
	redisadapter "auth-identity-service/internal/adapter/persistencia/redis"
	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/service"
)

// VerifyHandler procesa POST /verify-email y GET alias ?token=.
// Límite 4KB, exactamente uno de token|code, anti-oráculo (400 único genérico).
func VerifyHandler(svc *service.VerifyEmailService, limiter *redisadapter.RateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
			w.Header().Set("X-Request-ID", reqID)
		}
		if r.Method == http.MethodGet {
			// Alias Magic Link (idempotente, anti-prefetch: segundo GET → already_verified).
			tok := r.URL.Query().Get("token")
			verifyWith(w, r, svc, limiter, tok, "")
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(dto.NewError("UNSUPPORTED_MEDIA_TYPE",
				"Content-Type debe ser application/json.", nil))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		if r.ContentLength > 4<<10 {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			_ = json.NewEncoder(w).Encode(dto.NewError("PAYLOAD_TOO_LARGE", "Cuerpo demasiado grande.", nil))
			return
		}
		var req dto.VerifyRequest
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
		var token, code string
		if req.Token != nil {
			token = *req.Token
		}
		if req.Code != nil {
			code = *req.Code
		}
		verifyWith(w, r, svc, limiter, token, code)
	}
}

func verifyWith(w http.ResponseWriter, r *http.Request, svc *service.VerifyEmailService, limiter *redisadapter.RateLimiter, token, code string) {
	reqID := r.Header.Get("X-Request-ID")
	// Rate-limit por hash de secreto 5/min (fast-reject sin tocar DB).
	// Se hashea el crudo (sin distinguir formato) para no oracular.
	if limiter != nil {
		raw := token + "|" + code
		sum := sha256.Sum256([]byte(raw))
		key := "rl:verify:tok:" + hex.EncodeToString(sum[:])
		if ok, retry, err := limiter.Allow(r.Context(), key, 5, time.Minute); err == nil && !ok {
			rateLimited(w, retry)
			return
		}
	}
	out, err := svc.Execute(r.Context(), service.VerifyEmailInput{
		Token: token, Code: code, RequestID: reqID, IP: clientIP(r),
	})
	if err != nil {
		var ve *service.ValidationError
		if errors.As(err, &ve) {
			details := make([]dto.ErrorDetail, 0, len(ve.Fields))
			for _, f := range ve.Fields {
				details = append(details, dto.ErrorDetail{Field: f.Field, Reason: f.Reason})
			}
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(dto.NewError("VALIDATION_FAILED", "Datos inválidos.", details))
			return
		}
		if errors.Is(err, auth.ErrInvalidOrExpired) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(dto.NewInvalidOrExpired())
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(dto.NewError("INTERNAL_ERROR", "No pudimos procesar tu solicitud.", nil))
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(dto.NewVerifySuccess(out.Status))
}

func rateLimited(w http.ResponseWriter, retry time.Duration) {
	secs := int(retry.Seconds()) + 1
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	w.Header().Set("X-RateLimit-Remaining", "0")
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(dto.NewError("RATE_LIMITED",
		"Demasiadas solicitudes. Intenta de nuevo.", nil))
}
