package middleware

import (
	"encoding/json"
	"net/http"
)

// Recover convierte pánicos en 500 genérico sin stack.
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success": false,
					"error": map[string]any{
						"code": "INTERNAL_ERROR", "message": "No pudimos procesar tu solicitud.", "details": []any{},
					},
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}
