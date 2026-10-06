package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"auth-identity-service/internal/adapter/http/dto"
	"auth-identity-service/internal/adapter/http/middleware"
	redisadapter "auth-identity-service/internal/adapter/persistencia/redis"
	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/user"
	"auth-identity-service/internal/service"
)

// mfaAuthed extrae identidad del middleware (handlers tras RequireAuth).
func mfaAuthed(r *http.Request) (service.AuthUser, bool) {
	uid, at, ok := middleware.AuthUserFromContext(r.Context())
	if !ok {
		return service.AuthUser{}, false
	}
	return service.AuthUser{ID: uid, AuthTime: at}, true
}

func mfaUnauthorized(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(dto.NewError("UNAUTHORIZED", "Autenticación requerida.", nil))
}

// MFASetupHandler POST /mfa/totp/setup (auth + Step-Up).
func MFASetupHandler(svc *service.MFAService, limiter *redisadapter.RateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		au, ok := mfaAuthed(r)
		if !ok {
			mfaUnauthorized(w)
			return
		}
		if limiter != nil {
			if allow, retry, lerr := limiter.Allow(r.Context(),
				"rl:mfa:setup:"+au.ID, 10, time.Hour); lerr == nil && !allow {
				rateLimited(w, retry)
				return
			}
		}
		out, err := svc.Setup(r.Context(), service.SetupInput{
			User: au, RequestID: r.Header.Get("X-Request-ID"),
		})
		if err != nil {
			writeMFAError(w, err)
			return
		}
		var resp dto.MFASetupResponse
		resp.Success = true
		resp.Data.SecretB32 = out.SecretB32
		resp.Data.OTPAuthURL = out.OTPAuthURL
		resp.Data.ExpiresIn = out.ExpiresIn
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// MFAEnableHandler POST /mfa/totp/enable {code} (auth + Step-Up).
func MFAEnableHandler(svc *service.MFAService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		au, ok := mfaAuthed(r)
		if !ok {
			mfaUnauthorized(w)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		var req struct {
			Code string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(dto.NewError("INVALID_JSON", "Datos inválidos.", nil))
			return
		}
		out, err := svc.Enable(r.Context(), service.EnableInput{
			User: au, Code: strings.TrimSpace(req.Code), RequestID: r.Header.Get("X-Request-ID"),
		})
		if err != nil {
			writeMFAError(w, err)
			return
		}
		var resp dto.MFAEnableResponse
		resp.Success = true
		resp.Data.Status = out.Status
		resp.Data.BackupCodes = out.BackupCodes
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// MFAVerifyHandler POST /mfa/verify {mfa_token, code} (SIN Bearer).
func MFAVerifyHandler(svc *service.MFAService, limiter *redisadapter.RateLimiter, secureCookies bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(dto.NewError("UNSUPPORTED_MEDIA_TYPE",
				"Content-Type debe ser application/json.", nil))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		var req dto.MFAVerifyRequest
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(dto.NewError("INVALID_JSON", "Datos inválidos.", nil))
			return
		}
		// Rate por IP 20/min (challenge 5/min lo cubre el fails/burn del store).
		if limiter != nil {
			if allow, retry, lerr := limiter.Allow(r.Context(),
				"rl:mfa:verify:ip:"+clientIP(r), 20, time.Minute); lerr == nil && !allow {
				rateLimited(w, retry)
				return
			}
		}
		// Alias backup_code (ambos presentes → 400 sin consumir intento).
		if req.Code != "" && req.BackupCode != "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(dto.NewError("VALIDATION_FAILED", "Datos inválidos.", nil))
			return
		}
		out, err := svc.Verify(r.Context(), service.VerifyInput{
			MFAToken: req.MFAToken, Code: pickMFACode(req),
			RequestID: r.Header.Get("X-Request-ID"), IP: clientIP(r), UserAgent: r.UserAgent(),
		})
		if err != nil {
			writeMFAError(w, err)
			return
		}
		// CU-AUTH-04 híbrida (igual que login). Backup incluye remaining/warning en body.
		if out.Method == "backup" {
			w.Header().Set("Cache-Control", "no-store")
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
				"status": "active", "access_token": out.Session.AccessToken,
				"token_type": "Bearer", "expires_in": 900, "sid": out.Session.SID,
				"backup_remaining": out.Remaining, "backup_warning": out.Warning,
				"backup_exhausted": out.Exhausted,
			}
			if isNative {
				data["refresh_token"] = out.Session.RefreshTokenID
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": data})
			return
		}
		WritePair(w, out.Session, r, secureCookies)
		return
	}
}

// pickMFACode elige backup_code alias o code (autodetección en servicio).
func pickMFACode(req dto.MFAVerifyRequest) string {
	if strings.TrimSpace(req.BackupCode) != "" {
		return strings.TrimSpace(req.BackupCode)
	}
	return strings.TrimSpace(req.Code)
}

// MFARegenerateHandler POST /mfa/backup-codes/regenerate (auth + Step-Up).
func MFARegenerateHandler(svc *service.MFAService, limiter *redisadapter.RateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		au, ok := mfaAuthed(r)
		if !ok {
			mfaUnauthorized(w)
			return
		}
		if limiter != nil {
			if allow, retry, lerr := limiter.Allow(r.Context(),
				"rl:backup:regen:"+au.ID, 10, time.Hour); lerr == nil && !allow {
				rateLimited(w, retry)
				return
			}
		}
		out, err := svc.Regenerate(r.Context(), service.RegenerateInput{
			User: au, RequestID: r.Header.Get("X-Request-ID"),
		})
		if err != nil {
			writeMFAError(w, err)
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data": map[string]any{
				"backup_codes": out.Codes, "remaining": out.Remaining,
			},
		})
	}
}

// MFADisableHandler DELETE /mfa/totp (auth + Step-Up).
func MFADisableHandler(svc *service.MFAService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		au, ok := mfaAuthed(r)
		if !ok {
			mfaUnauthorized(w)
			return
		}
		out, err := svc.Disable(r.Context(), service.DisableInput{
			User: au, RequestID: r.Header.Get("X-Request-ID"),
		})
		if err != nil {
			writeMFAError(w, err)
			return
		}
		var resp dto.MFADisabledResponse
		resp.Success = true
		resp.Data.Status = out.Status
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// MFAStatusHandler GET /mfa/status (auth normal, sin frescura).
func MFAStatusHandler(svc *service.MFAService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		au, ok := mfaAuthed(r)
		if !ok {
			mfaUnauthorized(w)
			return
		}
		out, err := svc.Status(r.Context(), au.ID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(dto.NewError("INTERNAL_ERROR", "No pudimos procesar tu solicitud.", nil))
			return
		}
		var resp dto.MFAStatusResponse
		resp.Success = true
		resp.Data.Enabled = out.Enabled
		resp.Data.Methods = out.Methods
		resp.Data.BackupRemaining = out.Remaining
		resp.Data.BackupWarning = out.Warning
		if resp.Data.Methods == nil {
			resp.Data.Methods = []string{}
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func writeMFAError(w http.ResponseWriter, err error) {
	var ve *service.ValidationError
	if errors.As(err, &ve) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(dto.NewError("VALIDATION_FAILED", "Datos inválidos.", nil))
		return
	}
	switch {
	case errors.Is(err, user.ErrStepUpRequired):
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"error":   map[string]any{"code": "STEP_UP_REQUIRED", "message": "Confirma tu identidad de nuevo.", "details": []any{}},
			"meta":    map[string]any{"max_age": 300},
		})
	case errors.Is(err, auth.ErrInvalidMFA):
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(dto.NewInvalidMFA())
	case errors.Is(err, auth.ErrNoStaged), errors.Is(err, auth.ErrStagedExpired):
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(dto.NewError("NO_STAGED_SECRET", "Inicia la configuración de nuevo.", nil))
	case errors.Is(err, auth.ErrAlreadyEnabled):
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(dto.NewError("MFA_ALREADY_ENABLED", "MFA ya está activado.", nil))
	case errors.Is(err, user.ErrLastAuthFactor):
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(dto.NewError("LAST_AUTH_FACTOR", "Vincula otro acceso antes de quitar el único.", nil))
	case errors.Is(err, auth.ErrReplayUncheckable):
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(dto.NewError("REPLAY_UNCHECKABLE", "No pudimos verificar el reuso. Intenta de nuevo.", nil))
	case errors.Is(err, auth.ErrAccountUnavailable):
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(dto.NewError("ACCOUNT_UNAVAILABLE", "Cuenta no disponible.", nil))
	default:
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(dto.NewError("INTERNAL_ERROR", "No pudimos procesar tu solicitud.", nil))
	}
}
