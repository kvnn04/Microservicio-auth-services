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

// SessionsListHandler procesa GET /api/v1/auth/sessions (CU-SES-03 A).
// 200 {total, sessions[]} masked + current + no-store.
// 401 sin Bearer/malo/expirado. 429 con Retry-After. 500 PG-down
// (jamás 200 [] falso).
func SessionsListHandler(svc *service.ListSessionsService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
			w.Header().Set("X-Request-ID", reqID)
		}
		out, err := svc.Execute(r.Context(), service.ListSessionsInput{
			Bearer:    logoutBearer(r),
			RequestID: r.Header.Get("X-Request-ID"),
			IP:        logoutClientIP(r),
		})
		if err != nil {
			writeSessionsListError(w, err)
			return
		}
		items := make([]dto.SessionListItem, 0, len(out.Sessions))
		for _, v := range out.Sessions {
			var loc *string
			if v.Location != "" {
				l := v.Location
				loc = &l
			}
			items = append(items, dto.SessionListItem{
				SID: v.SID, DeviceLabel: v.DeviceLabel, IPMasked: v.IPMasked,
				Location: loc, CreatedAt: v.CreatedAt.UTC().Format(time.RFC3339),
				LastSeenAt: v.LastSeen.UTC().Format(time.RFC3339), Current: v.Current,
			})
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(dto.NewSessionsListResult(out.Total, items))
	}
}

func writeSessionsListError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrLogoutUnauthorized):
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(dto.NewLogoutUnauthorized())
	case errors.Is(err, auth.ErrRateLimited):
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(dto.NewLogoutRateLimited())
	default:
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(dto.NewError("INTERNAL_ERROR", "No pudimos procesar tu solicitud.", nil))
	}
}

// RevokeOneHandler procesa DELETE /api/v1/auth/sessions/:sid (CU-SES-03 B).
// 200 {revoked, sid} (actual intacta). 400 USE_LOGOUT (actual) /
// VALIDATION_FAILED (:sid no-UUID). 404 SESSION_NOT_FOUND único idéntico
// (ajena/inexistente/muerta, supuesto Q4). 429 horario. 500 sin cambios.
func RevokeOneHandler(svc *service.RevokeSessionService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
			w.Header().Set("X-Request-ID", reqID)
		}
		out, err := svc.Execute(r.Context(), service.RevokeSessionInput{
			Bearer:    logoutBearer(r),
			TargetSID: strings.TrimSpace(r.PathValue("sid")),
			RequestID: r.Header.Get("X-Request-ID"),
			IP:        logoutClientIP(r),
		})
		if err != nil {
			writeRevokeOneError(w, err)
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(dto.NewRevokeOneResult(out.SID))
	}
}

func writeRevokeOneError(w http.ResponseWriter, err error) {
	var ve *service.ValidationError
	if errors.As(err, &ve) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(dto.NewSessionsValidationFailed())
		return
	}
	switch {
	case errors.Is(err, auth.ErrUseLogout):
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(dto.NewUseLogout())
	case errors.Is(err, auth.ErrSessionNotFound):
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(dto.NewSessionNotFound())
	case errors.Is(err, auth.ErrLogoutUnauthorized):
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(dto.NewLogoutUnauthorized())
	case errors.Is(err, auth.ErrRateLimited):
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(dto.NewLogoutRateLimited())
	default:
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(dto.NewError("INTERNAL_ERROR", "No pudimos procesar tu solicitud.", nil))
	}
}
