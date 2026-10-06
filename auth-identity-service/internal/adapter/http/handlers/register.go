package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"auth-identity-service/internal/adapter/http/dto"
	httperrs "auth-identity-service/internal/adapter/http/errors"
	"auth-identity-service/internal/domain/shared"
	"auth-identity-service/internal/service"
)

// termsOutdatedResponse construye el 400 TERMS_OUTDATED con meta.active.
func termsOutdatedResponse(field string, oe *shared.TermsOutdatedError) dto.ErrorResponseWithMeta {
	return dto.NewTermsOutdated(field, oe.ActiveTerms, oe.ActivePrivacy)
}

// RegisterHandler POST /api/v1/auth/register. Límite 32KB, nunca expone user_id.
func RegisterHandler(svc *service.RegisterUserService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		reqID := r.Header.Get("X-Request-ID")
		if reqID != "" {
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
		var req dto.RegisterRequest
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
			_ = json.NewEncoder(w).Encode(dto.NewError("INVALID_JSON", "La solicitud contiene datos inválidos.", nil))
			return
		}
		out, err := svc.Execute(r.Context(), service.RegisterUserInput{
			EmailRaw: req.Email, Password: req.Password,
			TermsAccepted: req.TermsAccepted, TermsVersion: req.TermsVersion,
			PrivacyVersion: req.PrivacyVersion, RequestID: reqID,
			IP: clientIP(r), UserAgent: r.UserAgent(),
		})
		if err != nil {
			var ve *service.ValidationError
			if errors.As(err, &ve) {
				details := make([]dto.ErrorDetail, 0, len(ve.Fields))
				for _, f := range ve.Fields {
					details = append(details, dto.ErrorDetail{Field: f.Field, Reason: f.Reason})
				}
				code := "VALIDATION_FAILED"
				// CU-REG-05: cualquier detalle terms_* → TERMS_REQUIRED unificado.
				for _, d := range details {
					if strings.HasPrefix(d.Field, "terms") {
						code = "TERMS_REQUIRED"
						break
					}
				}
				msg := "La solicitud contiene datos inválidos."
				if code == "TERMS_REQUIRED" {
					msg = "Debes aceptar los términos y la política vigentes."
				}
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(dto.NewError(code, msg, details))
				return
			}
			// CU-REG-05: versión desactualizada → 400 + meta.active (públicas).
			var oe *shared.TermsOutdatedError
			if errors.As(err, &oe) {
				field := "terms_version"
				if req.TermsVersion == oe.ActiveTerms {
					field = "privacy_version"
				}
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(termsOutdatedResponse(field, oe))
				return
			}
			status, code := httperrs.MapDomainError(err)
			if status == http.StatusTooManyRequests {
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(dto.NewError(code,
					"Demasiadas solicitudes. Intenta de nuevo en unos segundos.", nil))
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(dto.NewError("INTERNAL_ERROR", "No pudimos procesar tu solicitud.", nil))
			return
		}
		_ = out
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(dto.NewRegisterSuccess())
	}
}

func clientIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		return v
	}
	return r.RemoteAddr
}
