package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"auth-identity-service/internal/adapter/http/dto"
	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/service"
)

// LogoutHandler procesa POST /api/v1/auth/logout (CU-SES-01).
// Acepta Bearer actual (Authorization header, NUNCA solo cookie — anti-CSRF)
// o {refresh_token} alternativo en body. Body ≤4KB (ignorado salvo refresh).
// 200 logged_out|already_logged_out + Clear-Cookie MISMO Path que Issue +
// no-store. 401 sin identificador/vencido/malo. 429 con Retry-After.
// 500 PG-down SIN Clear-Cookie (reintentable, no finge).
func LogoutHandler(svc *service.LogoutService, secureCookies bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
			w.Header().Set("X-Request-ID", reqID)
		}

		bearer := logoutBearer(r)
		refresh := logoutRefreshFromBody(w, r)
		// Si el body excedió 4KB, logoutRefreshFromBody ya respondió 413.
		if refresh == "__too_large__" {
			return
		}

		out, err := svc.Execute(r.Context(), service.LogoutInput{
			Bearer:       bearer,
			RefreshToken: refresh,
			RequestID:    r.Header.Get("X-Request-ID"),
			IP:           logoutClientIP(r),
		})
		if err != nil {
			writeLogoutError(w, err)
			return
		}
		// Éxito: Clear-Cookie con MISMO Path/Domain/SameSite que Issue (RN-05).
		// El front DEBE borrar Access de memoria y redirigir a login.
		http.SetCookie(w, &http.Cookie{
			Name: "refresh_token", Value: "",
			Path:     auth.LogoutRefreshPath,
			HttpOnly: true, Secure: secureCookies, SameSite: http.SameSiteLaxMode,
			MaxAge: 0,
		})
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(dto.NewLogoutResult(out.Status))
	}
}

// logoutBearer extrae Authorization: Bearer <jwt> (sin cookie, anti-CSRF).
func logoutBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

// logoutRefreshFromBody lee {refresh_token} optativo (≤4KB).
// Body irrelevante se ignora (sin 400); si excede 4KB responde 413.
// Retorna "" si no hay, "__too_large__" si ya respondió 413.
func logoutRefreshFromBody(w http.ResponseWriter, r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	if r.ContentLength > int64(auth.LogoutBodyMax) {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_ = json.NewEncoder(w).Encode(dto.NewError("PAYLOAD_TOO_LARGE", "Cuerpo demasiado grande.", nil))
		return "__too_large__"
	}
	r.Body = http.MaxBytesReader(w, r.Body, int64(auth.LogoutBodyMax))
	var req dto.LogoutRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		// Vacío o inválido → se ignora (sin 400, §4.1).
		if strings.Contains(err.Error(), "request body too large") {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			_ = json.NewEncoder(w).Encode(dto.NewError("PAYLOAD_TOO_LARGE", "Cuerpo demasiado grande.", nil))
			return "__too_large__"
		}
		return ""
	}
	if req.RefreshToken == nil {
		return ""
	}
	return strings.TrimSpace(*req.RefreshToken)
}

func logoutClientIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		if i := strings.Index(v, ","); i >= 0 {
			return strings.TrimSpace(v[:i])
		}
		return strings.TrimSpace(v)
	}
	return r.RemoteAddr
}

func writeLogoutError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrLogoutUnauthorized):
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(dto.NewLogoutUnauthorized())
	case errors.Is(err, auth.ErrRateLimited):
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(dto.NewLogoutRateLimited())
	default:
		// PG down y resto → 500 SIN Clear-Cookie (no finge logout).
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(dto.NewError("INTERNAL_ERROR", "No pudimos procesar tu solicitud.", nil))
	}
}
