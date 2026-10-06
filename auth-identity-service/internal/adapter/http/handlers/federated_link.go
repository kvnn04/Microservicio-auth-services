package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"auth-identity-service/internal/adapter/http/dto"
	"auth-identity-service/internal/adapter/http/middleware"
	redisadapter "auth-identity-service/internal/adapter/persistencia/redis"
	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/user"
	"auth-identity-service/internal/service"
)

// LinkInitiateHandler POST /federated/{provider}/link (auth + Step-Up).
func LinkInitiateHandler(svc *service.LinkService, limiter *redisadapter.RateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		uid, authTime, ok := middleware.AuthUserFromContext(r.Context())
		if !ok {
			writeLinkUnauthorized(w)
			return
		}
		provider := linkProvider(r)
		// Rate 10/hora/user.
		if limiter != nil {
			if allow, retry, lerr := limiter.Allow(r.Context(),
				"rl:link:init:"+uid, 10, time.Hour); lerr == nil && !allow {
				rateLimited(w, retry)
				return
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		var req dto.LinkInitiateRequest
		_ = json.NewDecoder(r.Body).Decode(&req) // body opcional (solo password)
		out, err := svc.Initiate(r.Context(), service.LinkInitiateInput{
			User: service.AuthUser{ID: uid, AuthTime: authTime},
			Provider: provider, CurrentPassword: req.CurrentPassword,
			RequestID: r.Header.Get("X-Request-ID"), IP: clientIP(r),
		})
		if err != nil {
			writeLinkError(w, err)
			return
		}
		var resp dto.LinkInitiateResponse
		resp.Success = true
		resp.Data.URL = out.URL
		resp.Data.State = out.State
		resp.Data.ExpiresIn = out.ExpiresIn
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// LinkCallbackHandler GET /federated/{provider}/link/callback (auth + Step-Up).
func LinkCallbackHandler(svc *service.LinkService, limiter *redisadapter.RateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		uid, authTime, ok := middleware.AuthUserFromContext(r.Context())
		if !ok {
			writeLinkUnauthorized(w)
			return
		}
		provider := linkProvider(r)
		q := r.URL.Query()
		if limiter != nil && q.Get("state") != "" {
			sum := sha256hex(q.Get("state"))
		 if allow, retry, lerr := limiter.Allow(r.Context(),
				"rl:link:cb:"+sum, 5, time.Minute); lerr == nil && !allow {
				rateLimited(w, retry)
				return
			}
		}
		out, err := svc.Callback(r.Context(), service.LinkCallbackInput{
			User: service.AuthUser{ID: uid, AuthTime: authTime},
			Provider: provider, Code: q.Get("code"), State: q.Get("state"),
			RequestID: r.Header.Get("X-Request-ID"), IP: clientIP(r),
		})
		if err != nil {
			writeLinkError(w, err)
			return
		}
		var resp dto.LinkStatusResponse
		resp.Success = true
		resp.Data.Status = out.Status
		resp.Data.Provider = out.Provider
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// UnlinkHandler DELETE /federated/{provider} y POST /:provider/unlink.
func UnlinkHandler(svc *service.UnlinkService, limiter *redisadapter.RateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		uid, authTime, ok := middleware.AuthUserFromContext(r.Context())
		if !ok {
			writeLinkUnauthorized(w)
			return
		}
		provider := linkProvider(r)
		if limiter != nil {
			if allow, retry, lerr := limiter.Allow(r.Context(),
				"rl:unlink:"+uid, 10, time.Hour); lerr == nil && !allow {
				rateLimited(w, retry)
				return
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		var req dto.UnlinkRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		out, err := svc.Unlink(r.Context(), service.UnlinkInput{
			User: service.AuthUser{ID: uid, AuthTime: authTime},
			Provider: provider, CurrentPassword: req.CurrentPassword,
			RequestID: r.Header.Get("X-Request-ID"), IP: clientIP(r),
		})
		if err != nil {
			writeLinkError(w, err)
			return
		}
		var resp dto.LinkStatusResponse
		resp.Success = true
		resp.Data.Status = out.Status
		resp.Data.Provider = out.Provider
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// LinkedListHandler GET /federated/linked (Bearer normal, sin frescura).
func LinkedListHandler(svc *service.UnlinkService, limiter *redisadapter.RateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		uid, _, ok := middleware.AuthUserFromContext(r.Context())
		if !ok {
			writeLinkUnauthorized(w)
			return
		}
		if limiter != nil {
			if allow, retry, lerr := limiter.Allow(r.Context(),
				"rl:linked:"+uid, 60, time.Minute); lerr == nil && !allow {
				rateLimited(w, retry)
				return
			}
		}
		items, err := svc.List(r.Context(), uid, "")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(dto.NewError("INTERNAL_ERROR", "No pudimos procesar tu solicitud.", nil))
			return
		}
		var resp dto.LinkedListResponse
		resp.Success = true
		resp.Data.Linked = make([]dto.LinkedListItem, 0, len(items))
		for _, it := range items {
			resp.Data.Linked = append(resp.Data.Linked, dto.LinkedListItem{
				Provider: it.Provider, EmailMasked: it.EmailMasked,
				SubHash: it.SubHash, LinkedAt: it.LinkedAt,
			})
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func linkProvider(r *http.Request) string {
	if p := r.PathValue("provider"); p != "" {
		return p
	}
	return "google"
}

func writeLinkUnauthorized(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(dto.NewError("UNAUTHORIZED", "Autenticación requerida.", nil))
}

func writeLinkError(w http.ResponseWriter, err error) {
	var ve *service.ValidationError
	if errors.As(err, &ve) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(dto.NewError("VALIDATION_FAILED", "Datos inválidos.", nil))
		return
	}
	switch {
	case errors.Is(err, auth.ErrProviderNotSupported):
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(dto.NewError("PROVIDER_NOT_SUPPORTED", "Proveedor no soportado.", nil))
	case errors.Is(err, user.ErrStepUpRequired):
		w.Header().Set("X-Step-Up-Max-Age", "300")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"error":   map[string]any{"code": "STEP_UP_REQUIRED", "message": "Confirma tu identidad de nuevo.", "details": []any{}},
			"meta":    map[string]any{"max_age": 300},
		})
	case errors.Is(err, user.ErrInvalidStepUp):
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(dto.NewError("INVALID_STEP_UP", "No pudimos confirmarte.", nil))
	case errors.Is(err, auth.ErrInvalidState):
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(dto.NewError("INVALID_LINK_STATE", "Flujo inválido o expirado.", nil))
	case errors.Is(err, auth.ErrInvalidCode):
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(dto.NewError("INVALID_FEDERATED_CODE", "No pudimos validarte con Google.", nil))
	case errors.Is(err, auth.ErrInvalidToken):
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(dto.NewError("INVALID_ID_TOKEN", "No pudimos validarte con Google.", nil))
	case errors.Is(err, user.ErrCollisionForeign):
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(dto.NewError("FEDERATED_ALREADY_LINKED", "Esta cuenta Google ya está vinculada a otra cuenta.", nil))
	case errors.Is(err, user.ErrProviderTaken):
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(dto.NewError("PROVIDER_ALREADY_LINKED", "Ya tienes este proveedor vinculado.", nil))
	case errors.Is(err, user.ErrLastAuthFactor):
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(dto.NewError("LAST_AUTH_FACTOR", "Vincula otro acceso antes de quitar el único.", nil))
	case errors.Is(err, user.ErrNotLinked):
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(dto.NewError("FEDERATED_NOT_LINKED", "Ese proveedor no está vinculado.", nil))
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

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
