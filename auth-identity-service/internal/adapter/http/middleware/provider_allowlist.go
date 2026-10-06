package middleware

import (
	"encoding/json"
	"net/http"
	"strings"
)

// ProviderAllowlist rechaza providers no habilitados con 404 (único 404
// permitido: por config, nunca por existencia de cuenta).
func ProviderAllowlist(allowed []string) func(http.Handler) http.Handler {
	set := map[string]bool{}
	for _, p := range allowed {
		set[strings.ToLower(strings.TrimSpace(p))] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := strings.ToLower(r.PathValue("provider"))
			if p == "" {
				p = "google"
			}
			if !set[p] {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success": false,
					"error": map[string]any{
						"code": "PROVIDER_NOT_SUPPORTED", "message": "Proveedor no soportado.", "details": []any{},
					},
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
