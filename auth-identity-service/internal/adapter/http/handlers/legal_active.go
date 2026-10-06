package handlers

import (
	"encoding/json"
	"net/http"

	adapterhttp "auth-identity-service/internal/adapter/http"
	"auth-identity-service/internal/adapter/persistencia/postgres"
	"auth-identity-service/internal/domain/shared"
)

// LegalActiveHandler GET /api/v1/legal/active (público, cacheable 1h).
// Degradado: stale:true + Warning si Redis/DB caen con fallback.
func LegalActiveHandler(provider *postgres.CombinedLegalProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		terms, privacy, stale, err := provider.GetActivePublic(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": false,
				"error":   map[string]any{"code": "INTERNAL_ERROR", "message": "No pudimos procesar tu solicitud.", "details": []any{}},
			})
			return
		}
		adapterhttp.SetActiveVersion("terms", terms.Version)
		adapterhttp.SetActiveVersion("privacy", privacy.Version)
		w.Header().Set("Cache-Control", "public, max-age=3600")
		if stale {
			w.Header().Set("Warning", "110 stale-legal-cache")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data": map[string]any{
				"terms":   legalDocJSON(terms),
				"privacy": legalDocJSON(privacy),
				"stale":   stale,
			},
		})
	}
}

func legalDocJSON(d shared.LegalDocument) map[string]any {
	return map[string]any{
		"version":        d.Version,
		"url":            d.URL,
		"content_hash":   "sha256:" + d.ContentHash,
		"effective_from": d.EffectiveFrom.UTC().Format("2006-01-02T15:04:05Z"),
	}
}
