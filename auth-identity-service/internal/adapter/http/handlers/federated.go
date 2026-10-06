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
	redisadapter "auth-identity-service/internal/adapter/persistencia/redis"
	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/shared"
	"auth-identity-service/internal/service"
)

// FederatedAuthorizeHandler GET /federated/{provider}/authorize → 302 + cookie.
// El provider llega validado por middleware allowlist (404 si no soportado).
func FederatedAuthorizeHandler(svc *service.RegisterFederatedService, secureCookies bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provider := r.PathValue("provider")
		if provider == "" {
			provider = "google"
		}
		if b := r.Header.Get("Authorization"); b != "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(dto.NewError("USE_LINK_FLOW",
				"Para vincular una cuenta inicia sesión primero.", nil))
			return
		}
		terms := r.URL.Query().Get("terms_accepted") == "true"
		out, err := svc.Authorize(r.Context(), service.AuthorizeInput{
			Provider: provider, ReturnTo: r.URL.Query().Get("return_to"),
			IP: clientIP(r), TermsAccepted: terms,
			TermsVersion: r.URL.Query().Get("terms_version"),
			PrivacyVersion: r.URL.Query().Get("privacy_version"),
		})
		if err != nil {
			writeFederatedError(w, err)
			return
		}
		cookie := &http.Cookie{
			Name: "fed_state", Value: out.State, Path: "/",
			HttpOnly: true, Secure: secureCookies, SameSite: http.SameSiteLaxMode,
			MaxAge: 600,
		}
		http.SetCookie(w, cookie)
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, out.URL, http.StatusFound)
	}
}

// FederatedCallbackHandler GET /federated/{provider}/callback → JSON.
func FederatedCallbackHandler(svc *service.RegisterFederatedService, limiter *redisadapter.RateLimiter, secureCookies bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		provider := r.PathValue("provider")
		if provider == "" {
			provider = "google"
		}
		// Borra cookie fed_state (un solo uso) en toda respuesta.
		http.SetCookie(w, &http.Cookie{Name: "fed_state", Value: "", Path: "/", MaxAge: -1})
		q := r.URL.Query()
		var bearer bool
		if b := r.Header.Get("Authorization"); b != "" {
			bearer = true
		}
		// Rate-limit por state 5/min (fast-reject, sin distinguir existencia).
		if limiter != nil && q.Get("state") != "" {
			sum := sha256.Sum256([]byte(q.Get("state")))
			if ok, retry, lerr := limiter.Allow(r.Context(),
				"rl:fed_cb:state:"+hex.EncodeToString(sum[:]), 5, time.Minute); lerr == nil && !ok {
				rateLimited(w, retry)
				return
			}
		}
		out, err := svc.Callback(r.Context(), service.CallbackInput{
			Provider: provider, Code: q.Get("code"), State: q.Get("state"),
			IdpError: q.Get("error"), RequestID: r.Header.Get("X-Request-ID"),
			IP: clientIP(r), UserAgent: r.UserAgent(), HasBearer: bearer,
		})
		if err != nil {
			writeFederatedError(w, err)
			return
		}
		// CU-AUTH-04 híbrida: si hay sesión, entrega tokens (web cookie + body).
		if out.Session != nil {
			isNative := IsNativeClient(r)
			if !isNative {
				http.SetCookie(w, &http.Cookie{
					Name: "refresh_token", Value: out.Session.RefreshTokenID,
					Path: "/api/v1/auth/refresh",
					HttpOnly: true, Secure: secureCookies, SameSite: http.SameSiteLaxMode,
					MaxAge: 30 * 24 * 3600,
				})
			}
			w.WriteHeader(http.StatusOK)
			data := map[string]any{
				"status": mapStatus(out.Status), "provider": provider,
				"access_token": out.Session.AccessToken, "token_type": "Bearer",
				"expires_in": 900, "sid": out.Session.SID,
			}
			if isNative {
				data["refresh_token"] = out.Session.RefreshTokenID
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": data})
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(dto.NewFederatedSuccess(mapStatus(out.Status), provider))
	}
}

func mapStatus(s string) string {
	if s == "pending_verification" {
		return s
	}
	return "active"
}

// setSessionCookies legacy (transición; producción usa híbrida inline).
func setSessionCookies(w http.ResponseWriter, access, refresh string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: "access_token", Value: access, Path: "/",
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: 900,
	})
	http.SetCookie(w, &http.Cookie{
		Name: "refresh_token", Value: refresh, Path: "/",
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: 7 * 24 * 3600,
	})
}

func writeFederatedError(w http.ResponseWriter, err error) {
	var ve *service.ValidationError
	if errors.As(err, &ve) {
		code := "VALIDATION_FAILED"
		for _, d := range ve.Fields {
			if strings.HasPrefix(d.Field, "terms") {
				code = "TERMS_REQUIRED"
				break
			}
		}
		w.WriteHeader(http.StatusBadRequest)
		details := make([]dto.ErrorDetail, 0, len(ve.Fields))
		for _, f := range ve.Fields {
			details = append(details, dto.ErrorDetail{Field: f.Field, Reason: f.Reason})
		}
		_ = json.NewEncoder(w).Encode(dto.NewError(code, "Debes aceptar los términos y la política vigentes.", details))
		return
	}
	var oe *shared.TermsOutdatedError
	if errors.As(err, &oe) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(dto.NewTermsOutdated("terms_version", oe.ActiveTerms, oe.ActivePrivacy))
		return
	}
	switch {
	case errors.Is(err, auth.ErrProviderNotSupported):
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(dto.NewError("PROVIDER_NOT_SUPPORTED", "Proveedor no soportado.", nil))
	case errors.Is(err, auth.ErrUseLinkFlow):
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(dto.NewError("USE_LINK_FLOW", "Para vincular una cuenta inicia sesión primero.", nil))
	case errors.Is(err, auth.ErrTermsRequired):
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(dto.NewError("TERMS_REQUIRED", "Debes aceptar los términos.", nil))
	case errors.Is(err, auth.ErrInvalidState):
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(dto.NewError("INVALID_FEDERATED_STATE", "Flujo inválido o expirado. Inicia de nuevo.", nil))
	case errors.Is(err, auth.ErrInvalidCode) || errors.Is(err, auth.ErrFederatedCancelled):
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(dto.NewError("INVALID_FEDERATED_CODE", "No pudimos validarte con Google.", nil))
	case errors.Is(err, auth.ErrInvalidToken) || errors.Is(err, auth.ErrIDPEmailMissing):
		code := "INVALID_ID_TOKEN"
		if errors.Is(err, auth.ErrIDPEmailMissing) {
			code = "IDP_EMAIL_MISSING"
		}
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(dto.NewError(code, "No pudimos validarte con Google.", nil))
	case errors.Is(err, auth.ErrLinkRequired):
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(dto.NewError("ACCOUNT_LINK_REQUIRED", "Esta dirección ya tiene cuenta. Inicia sesión para vincular.", nil))
	case errors.Is(err, auth.ErrIDPUnavailable):
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(dto.NewError("IDP_UNAVAILABLE", "Google no responde. Intenta en unos segundos.", nil))
	case errors.Is(err, auth.ErrAccountUnavailable):
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(dto.NewError("ACCOUNT_UNAVAILABLE", "Cuenta no disponible.", nil))
	default:
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(dto.NewError("INTERNAL_ERROR", "No pudimos procesar tu solicitud.", nil))
	}
}
