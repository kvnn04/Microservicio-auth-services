package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"auth-identity-service/internal/adapter/http/dto"
	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/service"
)

// RefreshHandler procesa POST /api/v1/auth/refresh (CU-SES-04).
// Refresh en cookie `refresh_token` (web) o body `{refresh_token}` (nativo);
// sin Bearer (el Access expirado no bloquea renovar). Body ≤4KB.
// 200 rotated (cookie rotada Max-Age restante real, mismo Path) /
// 409 CONCURRENT_ROTATION {retry} / 401 INVALID|EXPIRED|REVOKED|COMPROMISED /
// 429 / 500 (sin rotar ni quemar). Siempre `no-store`.
func RefreshHandler(svc *service.RotateService, secureCookies bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
			w.Header().Set("X-Request-ID", reqID)
		}

		refresh, tooLarge := refreshTokenFromRequest(w, r)
		if tooLarge {
			return
		}
		if refresh == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(dto.NewError("VALIDATION_FAILED", "Datos inválidos.", nil))
			return
		}

		out, err := svc.Execute(r.Context(), service.RotateInput{
			RefreshPlain: refresh,
			RequestID:    r.Header.Get("X-Request-ID"),
			IP:           logoutClientIP(r),
			UserAgent:    r.UserAgent(),
		})
		if err != nil {
			writeRefreshError(w, err)
			return
		}
		isNative := IsNativeClient(r)
		if !isNative {
			// Web: Refresh rotado en cookie acotada (MISMO Path que Issue).
			// Max-Age = restante real del sliding (ya acotado al absoluto).
			remaining := int(time.Until(out.RefreshExpiresAt).Seconds())
			http.SetCookie(w, &http.Cookie{
				Name: "refresh_token", Value: out.RefreshToken,
				Path:     auth.LogoutRefreshPath,
				HttpOnly: true, Secure: secureCookies, SameSite: http.SameSiteLaxMode,
				MaxAge: cookieMaxAge(remaining),
			})
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(dto.NewRefreshResult(
			out.AccessToken, out.RefreshToken, out.SID, out.ExpiresIn, isNative))
	}
}

// refreshTokenFromRequest: cookie primero (binding HttpOnly), fallback body.
// Retorna ("", true) si ya respondió 413.
func refreshTokenFromRequest(w http.ResponseWriter, r *http.Request) (string, bool) {
	if c, err := r.Cookie("refresh_token"); err == nil && strings.TrimSpace(c.Value) != "" {
		return strings.TrimSpace(c.Value), false
	}
	if r.Body == nil {
		return "", false
	}
	if r.ContentLength > int64(auth.RefreshBodyMax) {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_ = json.NewEncoder(w).Encode(dto.NewError("PAYLOAD_TOO_LARGE", "Cuerpo demasiado grande.", nil))
		return "", true
	}
	r.Body = http.MaxBytesReader(w, r.Body, int64(auth.RefreshBodyMax))
	var req dto.RefreshRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		if strings.Contains(err.Error(), "request body too large") {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			_ = json.NewEncoder(w).Encode(dto.NewError("PAYLOAD_TOO_LARGE", "Cuerpo demasiado grande.", nil))
			return "", true
		}
		return "", false
	}
	if req.RefreshToken == nil {
		return "", false
	}
	return strings.TrimSpace(*req.RefreshToken), false
}

// cookieMaxAge acota el Max-Age a 30d (el servicio ya acotó al absoluto).
func cookieMaxAge(expiresIn int) int {
	if expiresIn <= 0 {
		return 30 * 24 * 3600
	}
	if expiresIn > 30*24*3600 {
		return 30 * 24 * 3600
	}
	return expiresIn
}

func writeRefreshError(w http.ResponseWriter, err error) {
	var ve *service.ValidationError
	if errors.As(err, &ve) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(dto.NewError("VALIDATION_FAILED", "Datos inválidos.", nil))
		return
	}
	switch {
	case errors.Is(err, auth.ErrRefreshNotFound):
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(dto.NewInvalidRefresh())
	case errors.Is(err, auth.ErrRefreshExpired):
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(dto.NewSessionExpired())
	case errors.Is(err, auth.ErrRefreshRevoked):
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(dto.NewFamilyRevoked())
	case errors.Is(err, auth.ErrRefreshCompromised):
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(dto.NewSessionCompromised())
	case errors.Is(err, auth.ErrRefreshConcurrent):
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(dto.NewConcurrentRotation())
	case errors.Is(err, auth.ErrRateLimited):
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(dto.NewLogoutRateLimited())
	default:
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(dto.NewError("INTERNAL_ERROR", "No pudimos procesar tu solicitud.", nil))
	}
}
