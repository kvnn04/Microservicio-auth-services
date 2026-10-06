package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"auth-identity-service/internal/adapter/http/dto"
	httperrs "auth-identity-service/internal/adapter/http/errors"
	"auth-identity-service/internal/adapter/security"
	"auth-identity-service/internal/domain/user"
	"auth-identity-service/internal/service"
)

// EmailChangeConfirmHandler procesa POST /email/change/confirm y GET form.
// POST: 200 cambio / 400 opaco / 409 race-tomado. GET: 200 form si formato
// OK (nunca consume ni revela). Bearer opcional ligado al requester
// (ajeno → 400 opaco). `no-store` siempre.
func EmailChangeConfirmHandler(svc *service.EmailChangeConfirmService, verifier interface {
	VerifyBusiness(string) (*security.VerifiedSession, error)
}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
			w.Header().Set("X-Request-ID", reqID)
		}
		if r.Method == http.MethodGet {
			// Form: solo formato, sin lookup ni consumo (nunca oráculo).
			tok := r.URL.Query().Get("token")
			if _, err := user.ParseEmailChangeToken(tok); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(dto.NewError("VALIDATION_FAILED", "Datos inválidos.", nil))
				return
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"data":    map[string]any{"status": "change_form", "message": "Confirma el cambio con este enlace."},
			})
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(dto.NewError("UNSUPPORTED_MEDIA_TYPE",
				"Content-Type debe ser application/json.", nil))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		if r.ContentLength > 4<<10 {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			_ = json.NewEncoder(w).Encode(dto.NewError("PAYLOAD_TOO_LARGE", "Cuerpo demasiado grande.", nil))
			return
		}
		var req dto.EmailChangeConfirmRequest
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
		in := service.EmailChangeConfirmInput{
			Token: req.Token, RequestID: r.Header.Get("X-Request-ID"),
		}
		// Bearer opcional: se resuelve a user_id (inválido → 400 opaco).
		if h := r.Header.Get("Authorization"); h != "" {
			if parts := strings.SplitN(h, " ", 2); len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
				if raw := strings.TrimSpace(parts[1]); raw != "" {
					sess, verr := verifier.VerifyBusiness(raw)
					if verr != nil {
						w.WriteHeader(http.StatusBadRequest)
						_ = json.NewEncoder(w).Encode(dto.NewEmailChangeInvalidOrExpired())
						return
					}
					in.BearerUserID = sess.UserID
					in.HasBearer = true
				}
			}
		}
		out, err := svc.Execute(r.Context(), in)
		if err != nil {
			var ve *service.ValidationError
			if errors.As(err, &ve) {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(dto.NewError("VALIDATION_FAILED", "Datos inválidos.", nil))
				return
			}
			status, _ := httperrs.MapDomainError(err)
			if status == http.StatusConflict {
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(dto.NewEmailTaken())
				return
			}
			if status == http.StatusBadRequest {
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(dto.NewEmailChangeInvalidOrExpired())
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(dto.NewError("INTERNAL_ERROR", "No pudimos procesar tu solicitud.", nil))
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(dto.NewEmailChanged(out.Masked))
	}
}
