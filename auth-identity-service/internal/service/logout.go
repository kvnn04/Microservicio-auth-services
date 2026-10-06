package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/shared"

	"github.com/google/uuid"
)

// NoopLogoutMetrics default sin telemetría (tests).
type NoopLogoutMetrics struct{}

func (NoopLogoutMetrics) IncLogout(string)            {}
func (NoopLogoutMetrics) ObserveLogoutDuration(float64) {}
func (NoopLogoutMetrics) SetDenylistSize(float64)        {}

var _ auth.LogoutMetrics = NoopLogoutMetrics{}

// LogoutInput entrada del caso de uso (ya parseada del HTTP).
// Bearer: Access actual (con sid+jti). RefreshToken: plano alternativo
// del body (si viene sin Bearer). RequestID: X-Request-ID (idempotencia
// 24h). IP: cliente para rate-limit ip.
type LogoutInput struct {
	Bearer       string
	RefreshToken string
	RequestID    string
	IP           string
}

// LogoutOutput 200 (ambos): logged_out o already_logged_out.
type LogoutOutput struct {
	Status string
}

// LogoutService orquesta POST /logout (CU-SES-01).
// Solo puertos de dominio. Sin Step-Up, sin frescura, sin locks cuenta.
// Orden vinculante: verify → rate → idempotencia → revoke(Tx+Redis+
// denylist+outbox+audit) → 200. La fila de auditoría la escribe el Revoker
// en la misma Tx (1 commit); el servicio no hace INSERTs propios.
// PG down → 500 (sin Clear-Cookie, lo decide el handler).
// Redis down → 200 vía PG-fallback (lo decide el Revoker).
type LogoutService struct {
	Verifier auth.LogoutVerifier
	Revoker  auth.SessionRevoker
	Limiter  auth.LogoutLimiter
	Idem     shared.IdempotencyStore
	Metrics  auth.LogoutMetrics
	Tracer   TracerPort
	Now      func() time.Time
}

func NewLogoutService(
	verifier auth.LogoutVerifier,
	revoker auth.SessionRevoker,
	limiter auth.LogoutLimiter,
	idem shared.IdempotencyStore,
	metrics auth.LogoutMetrics,
	tracer TracerPort,
) *LogoutService {
	if metrics == nil {
		metrics = NoopLogoutMetrics{}
	}
	if tracer == nil {
		tracer = NoopTracer{}
	}
	return &LogoutService{
		Verifier: verifier, Revoker: revoker, Limiter: limiter,
		Idem: idem, Metrics: metrics, Tracer: tracer,
		Now: time.Now,
	}
}

func (s *LogoutService) nowUTC() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// Execute implementa §3: verify tolerante-revoked + exp exigible →
// rate → idempotencia → RevokeSID o ByRefresh → ok/already.
func (s *LogoutService) Execute(ctx context.Context, in LogoutInput) (*LogoutOutput, error) {
	start := time.Now()
	ctx, span := s.Tracer.Start(ctx, "UseCase.Logout")
	defer span.End()

	bearer := strings.TrimSpace(in.Bearer)
	refresh := strings.TrimSpace(in.RefreshToken)
	hasBearer := bearer != ""
	hasRefresh := refresh != ""

	if !hasBearer && !hasRefresh {
		s.Metrics.IncLogout("invalid")
		s.Metrics.ObserveLogoutDuration(time.Since(start).Seconds())
		return nil, auth.ErrLogoutUnauthorized
	}

	// Idempotencia RequestID 24h: replay devuelve mismo 200 sin re-revocar.
	// RequestID inválido/vacío → se omite (el middleware lo normaliza).
	requestID := strings.TrimSpace(in.RequestID)
	useIdem := false
	if requestID != "" {
		if _, err := uuid.Parse(requestID); err == nil && s.Idem != nil {
			useIdem = true
			if v, found, _ := s.Idem.Get(ctx, requestID); found {
				status := v
				if status != string(auth.LogoutLoggedOut) && status != string(auth.LogoutAlreadyLoggedOut) {
					status = string(auth.LogoutAlreadyLoggedOut)
				}
				s.Metrics.IncLogout(logoutResultLabel(status))
				s.Metrics.ObserveLogoutDuration(time.Since(start).Seconds())
				return &LogoutOutput{Status: status}, nil
			}
		}
	}

	// 1. Verify tolerante-revoked (solo firma+exp; denylist NO bloquea).
	// Si viene Bearer se usa (el refresh optativo se ignora: el sid ya
	// identifica la family exacta en la Tx).
	if hasBearer {
		return s.logoutByBearer(ctx, in, bearer, requestID, useIdem, start)
	}
	return s.logoutByRefresh(ctx, in, refresh, requestID, useIdem, start)
}

func (s *LogoutService) logoutByBearer(ctx context.Context, in LogoutInput, bearer, requestID string, useIdem bool, start time.Time) (*LogoutOutput, error) {
	_, verifySpan := s.Tracer.Start(ctx, "jwt.verify")
	claims, verr := s.verifyBearer(bearer)
	verifySpan.End()
	if verr != nil {
		s.Metrics.IncLogout("invalid")
		s.Metrics.ObserveLogoutDuration(time.Since(start).Seconds())
		return nil, auth.ErrLogoutUnauthorized
	}
	id := auth.LogoutIdentity{
		UserID: claims.Sub, SID: claims.SID, JTI: claims.JTI,
		ExpiresAt: time.Unix(claims.Exp, 0).UTC(),
	}
	if err := id.Validate(); err != nil {
		s.Metrics.IncLogout("invalid")
		s.Metrics.ObserveLogoutDuration(time.Since(start).Seconds())
		return nil, auth.ErrLogoutUnauthorized
	}

	// 2. Rate-check (sin revocar si excede): user 30/min + ip 60/min.
	_, rateSpan := s.Tracer.Start(ctx, "ratelimit")
	rerr := s.checkRate(ctx, id.UserID, in.IP)
	rateSpan.End()
	if rerr != nil {
		s.Metrics.IncLogout("rate_limited")
		s.Metrics.ObserveLogoutDuration(time.Since(start).Seconds())
		return nil, rerr
	}

	// 3. Revoke triple-capa (Tx PG + Redis + outbox).
	_, revokeSpan := s.Tracer.Start(ctx, "db.session.revoke")
	out, rverr := s.Revoker.RevokeSID(ctx, id)
	revokeSpan.End()
	if rverr != nil {
		if errors.Is(rverr, auth.ErrLogoutNotFound) {
			// Miss → already (idempotente 200; el Revoker dejó audit).
			s.Metrics.IncLogout("already")
			s.Metrics.ObserveLogoutDuration(time.Since(start).Seconds())
			s.putIdem(ctx, requestID, useIdem, string(auth.LogoutAlreadyLoggedOut))
			return &LogoutOutput{Status: string(auth.LogoutAlreadyLoggedOut)}, nil
		}
		s.Metrics.IncLogout("error")
		s.Metrics.ObserveLogoutDuration(time.Since(start).Seconds())
		return nil, fmt.Errorf("revoke: %w", auth.ErrSessionInfra)
	}
	status := string(out.Result)
	if status == "" {
		status = string(auth.LogoutLoggedOut)
	}
	// Auditoría: la escribe el Revoker en la misma Tx (result ok|already).
	if status == string(auth.LogoutAlreadyLoggedOut) {
		s.Metrics.IncLogout("already")
	} else {
		s.Metrics.IncLogout("ok")
	}
	s.Metrics.ObserveLogoutDuration(time.Since(start).Seconds())
	s.putIdem(ctx, requestID, useIdem, status)
	return &LogoutOutput{Status: status}, nil
}

func (s *LogoutService) logoutByRefresh(ctx context.Context, in LogoutInput, refresh, requestID string, useIdem bool, start time.Time) (*LogoutOutput, error) {
	// Formato: refresh opaco 43ch base64url (32B). Malformado → 401.
	if !isValidRefreshPlain(refresh) {
		s.Metrics.IncLogout("invalid")
		s.Metrics.ObserveLogoutDuration(time.Since(start).Seconds())
		return nil, auth.ErrLogoutUnauthorized
	}
	hash := logoutRefreshHash(refresh)

	// Rate por IP (60/min) + por hash (30/min) antes de revocar.
	_, rateSpan := s.Tracer.Start(ctx, "ratelimit")
	rerr := s.checkRateRefresh(ctx, hash, in.IP)
	rateSpan.End()
	if rerr != nil {
		s.Metrics.IncLogout("rate_limited")
		s.Metrics.ObserveLogoutDuration(time.Since(start).Seconds())
		return nil, rerr
	}

	_, revokeSpan := s.Tracer.Start(ctx, "db.session.revoke")
	out, rverr := s.Revoker.RevokeByRefreshHash(ctx, hash)
	revokeSpan.End()
	if rverr != nil {
		if errors.Is(rverr, auth.ErrLogoutNotFound) {
			s.Metrics.IncLogout("already")
			s.Metrics.ObserveLogoutDuration(time.Since(start).Seconds())
			s.putIdem(ctx, requestID, useIdem, string(auth.LogoutAlreadyLoggedOut))
			return &LogoutOutput{Status: string(auth.LogoutAlreadyLoggedOut)}, nil
		}
		s.Metrics.IncLogout("error")
		s.Metrics.ObserveLogoutDuration(time.Since(start).Seconds())
		return nil, fmt.Errorf("revoke refresh: %w", auth.ErrSessionInfra)
	}
	status := string(out.Result)
	if status == "" {
		status = string(auth.LogoutLoggedOut)
	}
	// Auditoría: la escribe el Revoker en la misma Tx.
	if status == string(auth.LogoutAlreadyLoggedOut) {
		s.Metrics.IncLogout("already")
	} else {
		s.Metrics.IncLogout("ok")
	}
	s.Metrics.ObserveLogoutDuration(time.Since(start).Seconds())
	s.putIdem(ctx, requestID, useIdem, status)
	return &LogoutOutput{Status: status}, nil
}

func (s *LogoutService) verifyBearer(bearer string) (auth.AccessClaims, error) {
	if s.Verifier == nil {
		return auth.AccessClaims{}, auth.ErrLogoutUnauthorized
	}
	// Soporta "Bearer <jwt>" o jwt pelado (el handler ya pela, doble-tolerante).
	tok := bearer
	if parts := strings.SplitN(bearer, " ", 2); len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
		tok = strings.TrimSpace(parts[1])
	}
	if tok == "" {
		return auth.AccessClaims{}, auth.ErrLogoutUnauthorized
	}
	claims, err := s.Verifier.Verify(tok)
	if err != nil {
		return auth.AccessClaims{}, err
	}
	// Exp exigible: expirado hace >skew → 401 (nada que matar que el
	// tiempo no haya matado). El verifier ya lo chequea, doble-guard aquí
	// con reloj inyectable para tests deterministas.
	now := s.nowUTC().Unix()
	if now > claims.Exp+int64((auth.ClockSkew/time.Second)) {
		return auth.AccessClaims{}, auth.ErrLogoutUnauthorized
	}
	return claims, nil
}

func (s *LogoutService) checkRate(ctx context.Context, userID, ip string) error {
	if s.Limiter == nil {
		return nil
	}
	if userID != "" {
		ok, _, lerr := s.Limiter.Allow(ctx, "logout:user:"+userID, auth.LogoutUserLimit, auth.LogoutRateWindow)
		if lerr == nil && !ok {
			return auth.ErrRateLimited
		}
	}
	if ip != "" {
		ok, _, lerr := s.Limiter.Allow(ctx, "logout:ip:"+ip, auth.LogoutIPLimit, auth.LogoutRateWindow)
		if lerr == nil && !ok {
			return auth.ErrRateLimited
		}
	}
	return nil
}

func (s *LogoutService) checkRateRefresh(ctx context.Context, hash, ip string) error {
	if s.Limiter == nil {
		return nil
	}
	if ip != "" {
		ok, _, lerr := s.Limiter.Allow(ctx, "logout:ip:"+ip, auth.LogoutIPLimit, auth.LogoutRateWindow)
		if lerr == nil && !ok {
			return auth.ErrRateLimited
		}
	}
	ok, _, lerr := s.Limiter.Allow(ctx, "logout:refresh:"+hash, auth.LogoutUserLimit, auth.LogoutRateWindow)
	if lerr == nil && !ok {
		return auth.ErrRateLimited
	}
	return nil
}

func (s *LogoutService) putIdem(ctx context.Context, requestID string, use bool, status string) {
	if !use || s.Idem == nil || requestID == "" {
		return
	}
	_ = s.Idem.Put(ctx, requestID, status, 24*time.Hour)
}

func logoutResultLabel(status string) string {
	if status == string(auth.LogoutLoggedOut) {
		return "ok"
	}
	return "already"
}

func logoutRefreshHash(plain string) string {
	h := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(h[:])
}

// isValidRefreshPlain valida forma del refresh opaco (43ch base64url).
// Acepta 40..64ch base64url (tolerante a variantes) sin exponer timing.
func isValidRefreshPlain(s string) bool {
	if len(s) < 40 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '=' {
			continue
		}
		return false
	}
	return true
}
