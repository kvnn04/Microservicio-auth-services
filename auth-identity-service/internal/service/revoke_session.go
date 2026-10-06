package service

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
	"time"

	"auth-identity-service/internal/domain/auth"

	"github.com/google/uuid"
)

// RevokeSessionInput bisturí sobre otra sesión propia (Bearer).
type RevokeSessionInput struct {
	Bearer    string
	TargetSID string
	RequestID string
	IP        string
}

// RevokeSessionOutput 200 del corte selectivo (actual intacta).
type RevokeSessionOutput struct {
	Status string
	SID    string
}

// RevokeSessionService orquesta DELETE /sessions/:sid (CU-SES-03 B).
// Solo puertos. Sin Step-Up/frescura (defensa inmediata).
// Sin idempotencia por RequestID: el repeat cae en miss→404 (§4.2).
// El jitter en 404 iguala tiempos hit/miss (anti-oráculo, supuesto Q4).
type RevokeSessionService struct {
	Verifier auth.LogoutVerifier
	Lister   auth.SessionLister
	Limiter  auth.LogoutLimiter
	Metrics  auth.SessionsMetrics
	Tracer   TracerPort
	Sleep    func(time.Duration)
	Now      func() time.Time
}

func NewRevokeSessionService(
	verifier auth.LogoutVerifier,
	lister auth.SessionLister,
	limiter auth.LogoutLimiter,
	metrics auth.SessionsMetrics,
	tracer TracerPort,
) *RevokeSessionService {
	if metrics == nil {
		metrics = NoopSessionsMetrics{}
	}
	if tracer == nil {
		tracer = NoopTracer{}
	}
	return &RevokeSessionService{
		Verifier: verifier, Lister: lister, Limiter: limiter,
		Metrics: metrics, Tracer: tracer, Sleep: time.Sleep,
		Now: time.Now,
	}
}

// Execute implementa §3.B: verify → formato → ≠actual → rate → RevokeOne.
func (s *RevokeSessionService) Execute(ctx context.Context, in RevokeSessionInput) (*RevokeSessionOutput, error) {
	start := time.Now()
	ctx, span := s.Tracer.Start(ctx, "UseCase.RevokeSession")
	defer span.End()

	bearer := strings.TrimSpace(in.Bearer)
	if bearer == "" {
		s.doneRevoke("invalid", start)
		return nil, auth.ErrLogoutUnauthorized
	}

	_, verifySpan := s.Tracer.Start(ctx, "jwt.verify")
	claims, verr := verifySessionBearer(s.Verifier, bearer, s.nowUTC())
	verifySpan.End()
	if verr != nil || claims.Sub == "" || claims.SID == "" {
		s.doneRevoke("invalid", start)
		return nil, auth.ErrLogoutUnauthorized
	}

	target := strings.TrimSpace(in.TargetSID)
	if _, err := uuid.Parse(target); err != nil {
		s.doneRevoke("invalid", start)
		return nil, &ValidationError{Fields: []FieldError{{Field: "sid", Reason: "INVALID_FORMAT"}}}
	}
	// Actual protegida por contrato (sin consumir rate ni tocar nada).
	if target == claims.SID {
		s.Metrics.IncRevokedOne("use_logout")
		s.Metrics.ObserveRevokeOneDuration(time.Since(start).Seconds())
		return nil, auth.ErrUseLogout
	}

	_, rateSpan := s.Tracer.Start(ctx, "ratelimit")
	rerr := checkSessionsRate(s.Limiter, ctx, "revoke-one:", claims.Sub, in.IP,
		auth.RevokeOneUserLimit, 0, auth.RevokeOneWindow)
	rateSpan.End()
	if rerr != nil {
		s.doneRevoke("rate_limited", start)
		return nil, rerr
	}

	_, revokeSpan := s.Tracer.Start(ctx, "db.session.revoke")
	out, gerr := s.Lister.RevokeOne(ctx, claims.Sub, claims.SID, target)
	revokeSpan.End()
	if gerr != nil {
		if errors.Is(gerr, auth.ErrSessionNotFound) {
			// 404 único idéntico (ajena/inexistente/muerta) + jitter
			// 10-20ms para no filtrar hit/miss por tiempo.
			s.jitterNotFound()
			s.doneRevoke("not_found", start)
			return nil, auth.ErrSessionNotFound
		}
		s.doneRevoke("error", start)
		return nil, wrapSessionInfra("revoke", gerr)
	}
	s.Metrics.IncRevokedOne("ok")
	s.Metrics.ObserveRevokeOneDuration(time.Since(start).Seconds())
	return &RevokeSessionOutput{Status: "revoked", SID: out.SID}, nil
}

func (s *RevokeSessionService) nowUTC() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *RevokeSessionService) doneRevoke(result string, start time.Time) {
	s.Metrics.IncRevokedOne(result)
	s.Metrics.ObserveRevokeOneDuration(time.Since(start).Seconds())
}

// jitterNotFound duerme 10-20ms CSPRNG (timing-oracle mitigation, Q4).
func (s *RevokeSessionService) jitterNotFound() {
	if s.Sleep == nil {
		return
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(auth.JitterNotFoundMax-auth.JitterNotFoundMin)+1))
	if err != nil {
		s.Sleep(auth.JitterNotFoundMin)
		return
	}
	s.Sleep(auth.JitterNotFoundMin + time.Duration(n.Int64()))
}
