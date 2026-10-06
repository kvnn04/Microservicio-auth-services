package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"auth-identity-service/internal/service"
)

// SessionTransport híbrido CU-AUTH-04 (sin rutas nuevas).
// Web (defecto): body {access_token, token_type, expires_in, sid} +
//   Set-Cookie refresh_token=<43ch>; HttpOnly; Secure; SameSite=Lax;
//   Path=/api/v1/auth/refresh; Max-Age=2592000. Access NUNCA en cookie.
// Nativo (X-Client-Type: native): body {access_token, refresh_token, ...}
//   sin Set-Cookie (keystore del cliente). Nunca en URL/query/logs.
// Siempre Cache-Control: no-store.
func WritePair(w http.ResponseWriter, sess *service.SessionData, r *http.Request, secureCookies bool) {
	w.Header().Set("Cache-Control", "no-store")
	isNative := strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Client-Type")), "native")
	if sess == nil {
		return
	}
	if isNative {
		// Nativo: doble-body, sin cookies.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data": map[string]any{
				"status": "active", "access_token": sess.AccessToken,
				"refresh_token": sess.RefreshTokenID, "token_type": "Bearer",
				"expires_in": 900, "sid": sess.SID,
			},
		})
		return
	}
	// Web: Access en body + Refresh en cookie acotada.
	secure := secureCookies
	// En local sin HTTPS, Secure se relaja solo con ENV=dev (WARN en logs).
	http.SetCookie(w, &http.Cookie{
		Name: "refresh_token", Value: sess.RefreshTokenID,
		Path: "/api/v1/auth/refresh",
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
		MaxAge: 30 * 24 * 3600,
	})
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"data": map[string]any{
			"status": "active", "access_token": sess.AccessToken,
			"token_type": "Bearer", "expires_in": 900, "sid": sess.SID,
		},
	})
}

// IsNativeClient helper para handlers que bifurcan 200/202.
func IsNativeClient(r *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Client-Type")), "native")
}
