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
	"auth-identity-service/internal/service"
)

// PlessVerifyHandler procesa POST /passwordless/verify y GET alias ?token=.
// 200 active (+transporte híbrido) / 202 mfa_required / 400 opaco único / 429.
func PlessVerifyHandler(svc *service.PasswordlessVerifyService, limiter *redisadapter.RateLimiter, secureCookies bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
			w.Header().Set("X-Request-ID", reqID)
		}
		if r.Method == http.MethodGet {
			// Alias Magic Link (single-use; prefetch quema — el email advierte
			// copiar el código; doble apertura → 400 salvo replay RequestID).
			plessVerifyWith(w, r, svc, limiter, secureCookies, r.URL.Query().Get("token"), "")
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
		var req dto.PlessVerifyRequest
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
		plessVerifyWith(w, r, svc, limiter, secureCookies, token, code)
	}
}

func plessVerifyWith(w http.ResponseWriter, r *http.Request, svc *service.PasswordlessVerifyService, limiter *redisadapter.RateLimiter, secureCookies bool, token, code string) {
	reqID := r.Header.Get("X-Request-ID")
	// Rate-limit por hash de secreto 5/min (fast-reject sin tocar DB).
	// Se hashea el crudo (sin distinguir formato) para no oracular.
	if limiter != nil {
		raw := token + "|" + code
		sum := sha256.Sum256([]byte(raw))
		key := "rl:pless:verify:tok:" + hex.EncodeToString(sum[:])
		if ok, retry, err := limiter.Allow(r.Context(), key, 5, time.Minute); err == nil && !ok {
			rateLimited(w, retry)
			return
		}
	}
	out, err := svc.Execute(r.Context(), service.PlessVerifyInput{
		Token: token, Code: code, RequestID: reqID,
		IP: clientIP(r), UserAgent: r.UserAgent(),
	})
	if err != nil {
		var ve *service.ValidationError
		if errors.As(err, &ve) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(dto.NewError("VALIDATION_FAILED", "Datos inválidos.", nil))
			return
		}
		status, code := httperrs.MapDomainError(err)
		switch status {
		case http.StatusTooManyRequests:
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(dto.NewError(code, "Demasiadas solicitudes.", nil))
			return
		case http.StatusBadRequest:
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(dto.NewPlessInvalidOrExpired())
			return
		default:
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(dto.NewError("INTERNAL_ERROR", "No pudimos procesar tu solicitud.", nil))
			return
		}
	}
	if out.Status == "mfa_required" && out.Challenge != nil {
		// 202 SIN cookies de sesión (pre-token aislado, igual login).
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(dto.NewMFARequired(
			out.Challenge.Token, out.Challenge.ExpiresIn))
		return
	}
	if out.Session != nil {
		// CU-AUTH-04 híbrida (sin WriteHeader previo: WritePair setea cookies).
		WritePair(w, out.Session, r, secureCookies)
		return
	}
	// Replay idempotente sin sesión (mismo RequestID): 200 genérico.
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(dto.NewPlessSent())
}
