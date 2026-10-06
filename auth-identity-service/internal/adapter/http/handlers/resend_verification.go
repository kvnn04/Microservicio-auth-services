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
	"auth-identity-service/internal/domain/user"
	redisadapter "auth-identity-service/internal/adapter/persistencia/redis"
	"auth-identity-service/internal/service"
)

// ResendHandler procesa POST /resend-verification.
// SIEMPRE 202 genérico exista o no (anti-enumeración). Límite 2KB.
func ResendHandler(svc *service.ResendService, limiter *redisadapter.RateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
			w.Header().Set("X-Request-ID", reqID)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			// Genérico igualmente para no oracular por Content-Type.
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(dto.NewResendQueued())
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 2<<10)
		if r.ContentLength > 2<<10 {
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(dto.NewResendQueued())
			return
		}
		var req dto.ResendRequest
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) || strings.Contains(err.Error(), "request body too large") {
				w.WriteHeader(http.StatusAccepted)
				_ = json.NewEncoder(w).Encode(dto.NewResendQueued())
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(dto.NewError("INVALID_JSON", "Datos inválidos.", nil))
			return
		}
		// Rate-limit por hash de email 3/hora. Al exceder se responde 202
		// genérico (NO 429: un 429 por email revelaría existencia — oráculo).
		if limiter != nil {
			if norm, _, nerr := user.Normalize(req.Email); nerr == nil {
				sum := sha256.Sum256([]byte(norm))
				if ok, _, lerr := limiter.Allow(r.Context(),
					"rl:resend:email:"+hex.EncodeToString(sum[:]), 3, time.Hour); lerr == nil && !ok {
					w.WriteHeader(http.StatusAccepted)
					_ = json.NewEncoder(w).Encode(dto.NewResendQueued())
					return
				}
			}
		}
		out, err := svc.Execute(r.Context(), service.ResendInput{
			EmailRaw: req.Email, RequestID: r.Header.Get("X-Request-ID"),
			IP: clientIP(r), UserAgent: r.UserAgent(),
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(dto.NewError("INTERNAL_ERROR", "No pudimos procesar tu solicitud.", nil))
			return
		}
		_ = out
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(dto.NewResendQueued())
	}
}
