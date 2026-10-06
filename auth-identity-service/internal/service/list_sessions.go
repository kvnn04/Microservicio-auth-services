package service

import (
	"context"
	"strings"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/shared"
)

// NoopSessionsMetrics default sin telemetría (tests, ambos servicios).
type NoopSessionsMetrics struct{}

func (NoopSessionsMetrics) IncListed(string)                {}
func (NoopSessionsMetrics) ObserveListDuration(float64)     {}
func (NoopSessionsMetrics) IncRevokedOne(string)            {}
func (NoopSessionsMetrics) ObserveRevokeOneDuration(float64) {}

var _ auth.SessionsMetrics = NoopSessionsMetrics{}

// ListSessionsInput lectura del propio inventario (Bearer).
type ListSessionsInput struct {
	Bearer    string
	RequestID string
	IP        string
}

// ListSessionsOutput lista ordenada last_seen DESC + total (≤20).
type ListSessionsOutput struct {
	Sessions []auth.SessionView
	Total    int
}

// ListSessionsService orquesta GET /sessions (CU-SES-03 A).
// Solo puertos. Sin Step-Up/frescura (visibilidad es defensa).
// Auditoría best-effort post-lectura (sin bus de eventos: no spamea).
type ListSessionsService struct {
	Verifier auth.LogoutVerifier
	Lister   auth.SessionLister
	Limiter  auth.LogoutLimiter
	Audit    shared.AuditLogger
	Metrics  auth.SessionsMetrics
	Tracer   TracerPort
	Now      func() time.Time
}

func NewListSessionsService(
	verifier auth.LogoutVerifier,
	lister auth.SessionLister,
	limiter auth.LogoutLimiter,
	audit shared.AuditLogger,
	metrics auth.SessionsMetrics,
	tracer TracerPort,
) *ListSessionsService {
	if metrics == nil {
		metrics = NoopSessionsMetrics{}
	}
	if tracer == nil {
		tracer = NoopTracer{}
	}
	if audit == nil {
		audit = NoopAudit{}
	}
	return &ListSessionsService{
		Verifier: verifier, Lister: lister, Limiter: limiter,
		Audit: audit, Metrics: metrics, Tracer: tracer,
		Now: time.Now,
	}
}

// Execute implementa §3.A: verify base → rate → List PG (Redis fast-path
// dentro del Lister) → marca Current → 200. PG down → 500 (nunca 200 []).
func (s *ListSessionsService) Execute(ctx context.Context, in ListSessionsInput) (*ListSessionsOutput, error) {
	start := time.Now()
	ctx, span := s.Tracer.Start(ctx, "UseCase.ListSessions")
	defer span.End()

	bearer := strings.TrimSpace(in.Bearer)
	if bearer == "" {
		s.Metrics.IncListed("invalid")
		s.Metrics.ObserveListDuration(time.Since(start).Seconds())
		return nil, auth.ErrLogoutUnauthorized
	}

	_, verifySpan := s.Tracer.Start(ctx, "jwt.verify")
	claims, verr := verifySessionBearer(s.Verifier, bearer, s.nowUTC())
	verifySpan.End()
	if verr != nil {
		s.Metrics.IncListed("invalid")
		s.Metrics.ObserveListDuration(time.Since(start).Seconds())
		return nil, auth.ErrLogoutUnauthorized
	}
	if claims.Sub == "" || claims.SID == "" {
		s.Metrics.IncListed("invalid")
		s.Metrics.ObserveListDuration(time.Since(start).Seconds())
		return nil, auth.ErrLogoutUnauthorized
	}

	_, rateSpan := s.Tracer.Start(ctx, "ratelimit")
	rerr := checkSessionsRate(s.Limiter, ctx, "sessions:list:", claims.Sub, in.IP,
		auth.ListUserLimit, auth.ListIPLimit, auth.ListRateWindow)
	rateSpan.End()
	if rerr != nil {
		s.Metrics.IncListed("rate_limited")
		s.Metrics.ObserveListDuration(time.Since(start).Seconds())
		return nil, rerr
	}

	_, dbSpan := s.Tracer.Start(ctx, "db.sessions.select")
	views, lerr := s.Lister.List(ctx, claims.Sub)
	dbSpan.End()
	if lerr != nil {
		s.Metrics.IncListed("error")
		s.Metrics.ObserveListDuration(time.Since(start).Seconds())
		return nil, wrapSessionInfra("list", lerr)
	}
	for i := range views {
		if views[i].SID == claims.SID {
			views[i].Current = true
		}
	}
	_ = s.Audit.Log(ctx, "session.list", map[string]string{
		"action": "session.list", "user_id": claims.Sub,
		"result": "ok", "total": itoaSessions(len(views)),
	})
	s.Metrics.IncListed("ok")
	s.Metrics.ObserveListDuration(time.Since(start).Seconds())
	return &ListSessionsOutput{Sessions: views, Total: len(views)}, nil
}

func (s *ListSessionsService) nowUTC() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}
