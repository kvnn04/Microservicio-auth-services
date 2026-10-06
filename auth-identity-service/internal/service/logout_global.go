package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/shared"

	"github.com/google/uuid"
)

// NoopGlobalMetrics default sin telemetría (tests).
type NoopGlobalMetrics struct{}

func (NoopGlobalMetrics) IncGlobal(string)              {}
func (NoopGlobalMetrics) ObserveGlobalDuration(float64) {}
func (NoopGlobalMetrics) ObserveSessionsRevoked(int)    {}

var _ auth.GlobalLogoutMetrics = NoopGlobalMetrics{}

// LogoutGlobalInput entrada del caso de uso (Bearer, sin refresh-alt:
// el corte global siempre identifica por sub del Access).
type LogoutGlobalInput struct {
	Bearer    string
	RequestID string
	IP        string
}

// LogoutGlobalOutput 200: corte aplicado (repeat → 0 revocadas, mismo shape).
type LogoutGlobalOutput struct {
	Status          string
	SessionsRevoked int
}

// LogoutGlobalService orquesta POST /logout-global (CU-SES-02).
// Solo puertos de dominio. Sin Step-Up/frescura (defensa inmediata);
// rate horaria anti-loop; idempotencia RequestID 24h (mismo 200 sin
// re-bumpear ni re-emitir). La auditoría+email viven en la Tx del Revoker.
type LogoutGlobalService struct {
	Verifier auth.LogoutVerifier
	Revoker  auth.GlobalSessionRevoker
	Limiter  auth.LogoutLimiter
	Idem     shared.IdempotencyStore
	Metrics  auth.GlobalLogoutMetrics
	Tracer   TracerPort
	Now      func() time.Time
}

func NewLogoutGlobalService(
	verifier auth.LogoutVerifier,
	revoker auth.GlobalSessionRevoker,
	limiter auth.LogoutLimiter,
	idem shared.IdempotencyStore,
	metrics auth.GlobalLogoutMetrics,
	tracer TracerPort,
) *LogoutGlobalService {
	if metrics == nil {
		metrics = NoopGlobalMetrics{}
	}
	if tracer == nil {
		tracer = NoopTracer{}
	}
	return &LogoutGlobalService{
		Verifier: verifier, Revoker: revoker, Limiter: limiter,
		Idem: idem, Metrics: metrics, Tracer: tracer,
		Now: time.Now,
	}
}

func (s *LogoutGlobalService) nowUTC() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// Execute implementa §3: verify base (firma+exp, sin fresh/denylist/
// valid_after para entrar) → rate → idempotencia → RevokeAll → 200.
func (s *LogoutGlobalService) Execute(ctx context.Context, in LogoutGlobalInput) (*LogoutGlobalOutput, error) {
	start := time.Now()
	ctx, span := s.Tracer.Start(ctx, "UseCase.LogoutGlobal")
	defer span.End()

	bearer := strings.TrimSpace(in.Bearer)
	if bearer == "" {
		s.Metrics.IncGlobal("invalid")
		s.Metrics.ObserveGlobalDuration(time.Since(start).Seconds())
		return nil, auth.ErrLogoutUnauthorized
	}

	// Idempotencia RequestID 24h: replay devuelve mismo 200 (M:N
	// almacenados) sin re-bumpear, sin re-emitir outbox ni email.
	requestID := strings.TrimSpace(in.RequestID)
	useIdem := false
	if requestID != "" {
		if _, err := uuid.Parse(requestID); err == nil && s.Idem != nil {
			useIdem = true
			if v, found, _ := s.Idem.Get(ctx, requestID); found {
				if m, ok := parseGlobalIdem(v); ok {
					s.Metrics.IncGlobal("ok")
					s.Metrics.ObserveSessionsRevoked(m)
					s.Metrics.ObserveGlobalDuration(time.Since(start).Seconds())
					return &LogoutGlobalOutput{Status: "logged_out_global", SessionsRevoked: m}, nil
				}
			}
		}
	}

	// 1. Verify tolerante: firma/kid/iss/aud/exp/sub. Expirado (no
	// identifica sub) o firma mala → 401, 0 cambios. Denylist y valid_after
	// NO bloquean la entrada: el corte debe funcionar aunque el llamante
	// venga de un logout individual o de otro corte (repeat).
	_, verifySpan := s.Tracer.Start(ctx, "jwt.verify")
	claims, verr := s.verifyBearer(bearer)
	verifySpan.End()
	if verr != nil {
		s.Metrics.IncGlobal("invalid")
		s.Metrics.ObserveGlobalDuration(time.Since(start).Seconds())
		return nil, auth.ErrLogoutUnauthorized
	}
	if claims.Sub == "" {
		s.Metrics.IncGlobal("invalid")
		s.Metrics.ObserveGlobalDuration(time.Since(start).Seconds())
		return nil, auth.ErrLogoutUnauthorized
	}

	// 2. Rate-check (sin cortar si excede): user 5/hora + ip 20/hora.
	_, rateSpan := s.Tracer.Start(ctx, "ratelimit")
	rerr := s.checkRate(ctx, claims.Sub, in.IP)
	rateSpan.End()
	if rerr != nil {
		s.Metrics.IncGlobal("rate_limited")
		s.Metrics.ObserveGlobalDuration(time.Since(start).Seconds())
		return nil, rerr
	}

	// 3. Corte total (Tx + sweep + pub + email dentro del Revoker).
	_, revokeSpan := s.Tracer.Start(ctx, "db.global_revoke")
	out, gerr := s.Revoker.RevokeAll(ctx, claims.Sub, in.IP)
	revokeSpan.End()
	if gerr != nil {
		if errors.Is(gerr, auth.ErrGlobalUserNotFound) {
			s.Metrics.IncGlobal("invalid")
			s.Metrics.ObserveGlobalDuration(time.Since(start).Seconds())
			return nil, auth.ErrLogoutUnauthorized
		}
		s.Metrics.IncGlobal("error")
		s.Metrics.ObserveGlobalDuration(time.Since(start).Seconds())
		return nil, fmt.Errorf("revoke all: %w", auth.ErrSessionInfra)
	}

	s.Metrics.IncGlobal("ok")
	s.Metrics.ObserveSessionsRevoked(out.Sessions)
	s.Metrics.ObserveGlobalDuration(time.Since(start).Seconds())
	s.putIdem(ctx, requestID, useIdem, out.Sessions, out.Families)
	return &LogoutGlobalOutput{Status: "logged_out_global", SessionsRevoked: out.Sessions}, nil
}

func (s *LogoutGlobalService) verifyBearer(bearer string) (auth.AccessClaims, error) {
	if s.Verifier == nil {
		return auth.AccessClaims{}, auth.ErrLogoutUnauthorized
	}
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
	now := s.nowUTC().Unix()
	if now > claims.Exp+int64((auth.ClockSkew/time.Second)) {
		return auth.AccessClaims{}, auth.ErrLogoutUnauthorized
	}
	return claims, nil
}

func (s *LogoutGlobalService) checkRate(ctx context.Context, userID, ip string) error {
	if s.Limiter == nil {
		return nil
	}
	if userID != "" {
		ok, _, lerr := s.Limiter.Allow(ctx, "logout-global:user:"+userID, auth.LogoutGlobalUserLimit, auth.LogoutGlobalRateWindow)
		if lerr == nil && !ok {
			return auth.ErrRateLimited
		}
	}
	if ip != "" {
		ok, _, lerr := s.Limiter.Allow(ctx, "logout-global:ip:"+ip, auth.LogoutGlobalIPLimit, auth.LogoutGlobalRateWindow)
		if lerr == nil && !ok {
			return auth.ErrRateLimited
		}
	}
	return nil
}

func (s *LogoutGlobalService) putIdem(ctx context.Context, requestID string, use bool, sessions, families int) {
	if !use || s.Idem == nil || requestID == "" {
		return
	}
	_ = s.Idem.Put(ctx, requestID, fmt.Sprintf("%d:%d", sessions, families), 24*time.Hour)
}

// parseGlobalIdem reconstruye M del valor "M:N" (N solo informativo).
func parseGlobalIdem(v string) (int, bool) {
	var m, n int
	if _, err := fmt.Sscanf(strings.TrimSpace(v), "%d:%d", &m, &n); err != nil {
		return 0, false
	}
	if m < 0 || n < 0 {
		return 0, false
	}
	return m, true
}
