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

// LogoutGlobalHandler procesa POST /api/v1/auth/logout-global (CU-SES-02).
// Bearer con sub de cualquier edad (sin frescura/Step-Up; entra aunque el
// llamante esté denylisteado o con valid_after viejo — el corte no espera).
// Body ≤4KB ignorado. 200 {logged_out_global, sessions_revoked} +
// Clear-Cookie MISMO Path que Issue + no-store. 401 sin identificador/
// expirado/malo. 429 horario con Retry-After. 500 PG-down SIN Clear-Cookie.
func LogoutGlobalHandler(svc *service.LogoutGlobalService, secureCookies bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
			w.Header().Set("X-Request-ID", reqID)
		}

		bearer := logoutBearer(r)
		// Body irrelevante (se ignora salvo límite): drena acotado para
		// no dejar el stream a medias; >4KB → 413 como en logout single.
		if tooLarge := drainLogoutBody(w, r); tooLarge {
			return
		}

		out, err := svc.Execute(r.Context(), service.LogoutGlobalInput{
			Bearer:    bearer,
			RequestID: r.Header.Get("X-Request-ID"),
			IP:        logoutClientIP(r),
		})
		if err != nil {
			writeLogoutGlobalError(w, err)
			return
		}
		// Clear-Cookie con MISMO Path/Domain/SameSite que Issue (RN SES-01).
		http.SetCookie(w, &http.Cookie{
			Name: "refresh_token", Value: "",
			Path:     auth.LogoutRefreshPath,
			HttpOnly: true, Secure: secureCookies, SameSite: http.SameSiteLaxMode,
			MaxAge: 0,
		})
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(dto.NewLogoutGlobalResult(out.SessionsRevoked))
	}
}

// drainLogoutBody consume el body con tope 4KB (ignora contenido).
// Retorna true si ya respondió 413.
func drainLogoutBody(w http.ResponseWriter, r *http.Request) bool {
	if r.Body == nil {
		return false
	}
	if r.ContentLength > int64(auth.LogoutBodyMax) {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_ = json.NewEncoder(w).Encode(dto.NewError("PAYLOAD_TOO_LARGE", "Cuerpo demasiado grande.", nil))
		return true
	}
	r.Body = http.MaxBytesReader(w, r.Body, int64(auth.LogoutBodyMax))
	var tmp struct {
		RefreshToken *string `json:"refresh_token,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&tmp); err != nil {
		if strings.Contains(err.Error(), "request body too large") {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			_ = json.NewEncoder(w).Encode(dto.NewError("PAYLOAD_TOO_LARGE", "Cuerpo demasiado grande.", nil))
			return true
		}
		// Vacío o inválido → se ignora (sin 400, §4.1).
	}
	return false
}

func writeLogoutGlobalError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrLogoutUnauthorized):
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(dto.NewLogoutUnauthorized())
	case errors.Is(err, auth.ErrRateLimited):
		// Buckets horarios: techo de ventana como Retry-After.
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(dto.NewLogoutRateLimited())
	default:
		// PG down y resto → 500 SIN Clear-Cookie (no finge el corte).
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(dto.NewError("INTERNAL_ERROR", "No pudimos procesar tu solicitud.", nil))
	}
}
