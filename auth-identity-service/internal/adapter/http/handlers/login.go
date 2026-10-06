package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"auth-identity-service/internal/adapter/http/dto"
	httperrs "auth-identity-service/internal/adapter/http/errors"
	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/service"
)

// LoginHandler POST /api/v1/auth/login.
// 200 active+cookies / 202 mfa_required / 400 / 401 único / 429 / 500.
// Veta 403/404/409/422/423 en este flujo (assert en tests).
func LoginHandler(svc *service.LoginService, secureCookies bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
			w.Header().Set("X-Request-ID", reqID)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(dto.NewError("UNSUPPORTED_MEDIA_TYPE",
				"Content-Type debe ser application/json.", nil))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
		if r.ContentLength > 32<<10 {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			_ = json.NewEncoder(w).Encode(dto.NewError("PAYLOAD_TOO_LARGE", "Cuerpo demasiado grande.", nil))
			return
		}
		var req dto.LoginRequest
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
		out, err := svc.Execute(r.Context(), service.LoginInput{
			EmailRaw: req.Email, Password: req.Password,
			RequestID: r.Header.Get("X-Request-ID"),
			IP:        clientIP(r), UserAgent: r.UserAgent(),
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
			status, code := httperrs.MapDomainError(err)
			switch status {
			case http.StatusTooManyRequests:
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(dto.NewError(code,
					"Demasiadas solicitudes.", nil))
				return
			case http.StatusUnauthorized:
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(dto.NewInvalidCredentials())
				return
			default:
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(dto.NewError("INTERNAL_ERROR", "No pudimos procesar tu solicitud.", nil))
				return
			}
		}
		if out.Status == "mfa_required" && out.Challenge != nil {
			// 202 SIN cookies de sesión (pre-token aislado).
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(dto.NewMFARequired(
				out.Challenge.Token, out.Challenge.ExpiresIn))
			return
		}
		// CU-AUTH-04 híbrida: web body Access + cookie Refresh acotada,
		// nativo doble-body (decide X-Client-Type). Siempre no-store.
		// Nota: WritePair setea cookies ANTES del body (sin WriteHeader previo).
		if out.Session != nil {
			WritePair(w, out.Session, r, secureCookies)
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(dto.NewLoginSuccess())
		_ = auth.ErrInvalidCredentials
	}
}

// setLoginCookies legacy (tests de transición; producción usa WritePair).
func setLoginCookies(w http.ResponseWriter, access, refresh string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: "access_token", Value: access, Path: "/",
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: 900,
	})
	http.SetCookie(w, &http.Cookie{
		Name: "refresh_token", Value: refresh, Path: "/",
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: 7 * 24 * 3600,
	})
}
