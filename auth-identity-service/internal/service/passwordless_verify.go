package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/shared"

	"github.com/google/uuid"
)

// PlessVerifyInput entrada verify (SIN Bearer; el secreto es la auth).
type PlessVerifyInput struct {
	Token     string
	Code      string
	RequestID string
	IP        string
	UserAgent string
}

// PlessVerifyOutput sesión final o desafío MFA (transporte híbrido en handler).
type PlessVerifyOutput struct {
	Status    string // "active" | "mfa_required"
	Session   *SessionData
	Challenge *MFAChallengeData
	Method    string // "link" | "otp"
	Risk      string // "low" | "high"
}

// PasswordlessVerifyService orquesta POST /passwordless/verify + GET alias.
// Todo fallo de secreto es 400 opaco (salvo 500 infra y 400 de forma).
// Delay 40-80ms en 400. Misma forma/tiempo para miss/expirado/consumido/quemado.
type PasswordlessVerifyService struct {
	Store      auth.PasswordlessStore
	Sessions   auth.SessionIssuer
	MFA        auth.MFAPreTokenIssuer
	Challenges auth.MFAChallengeStore
	Idem       shared.IdempotencyStore
	Audit      shared.AuditLogger
	Metrics    PlessMetricsPort
	Tracer     TracerPort
	Sleep      func(time.Duration)
}

func NewPasswordlessVerifyService(
	store auth.PasswordlessStore,
	sessions auth.SessionIssuer,
	mfa auth.MFAPreTokenIssuer,
	challenges auth.MFAChallengeStore,
	idem shared.IdempotencyStore,
	audit shared.AuditLogger,
	metrics PlessMetricsPort,
	tracer TracerPort,
) *PasswordlessVerifyService {
	if metrics == nil {
		metrics = NoopPlessMetrics{}
	}
	if tracer == nil {
		tracer = NoopTracer{}
	}
	if audit == nil {
		audit = NoopAudit{}
	}
	return &PasswordlessVerifyService{
		Store: store, Sessions: sessions, MFA: mfa, Challenges: challenges,
		Idem: idem, Audit: audit, Metrics: metrics, Tracer: tracer, Sleep: time.Sleep,
	}
}

func plessVerifyJitter() time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(41))
	if err != nil {
		return 40 * time.Millisecond
	}
	return 40*time.Millisecond + time.Duration(n.Int64())*time.Millisecond
}

// Execute implementa §3 pasos 6-8: forma→rate→find→compare→consume→risk→Issue/MFA.
func (s *PasswordlessVerifyService) Execute(ctx context.Context, in PlessVerifyInput) (*PlessVerifyOutput, error) {
	start := time.Now()
	ctx, span := s.Tracer.Start(ctx, "UseCase.PasswordlessVerify")
	defer span.End()

	hasToken := in.Token != ""
	hasCode := in.Code != ""
	if hasToken == hasCode {
		s.Metrics.IncPless("verify", "validation_failed")
		return nil, &ValidationError{Fields: []FieldError{{Field: "token", Reason: "EXACTLY_ONE_REQUIRED"}}}
	}
	var hash, method string
	if hasToken {
		h, err := auth.ParsePlessToken(in.Token)
		if err != nil {
			s.Metrics.IncPless("verify", "validation_failed")
			return nil, &ValidationError{Fields: []FieldError{{Field: "token", Reason: "INVALID_FORMAT"}}}
		}
		hash, method = h, "link"
	} else {
		h, err := auth.ParsePlessOTP(in.Code)
		if err != nil {
			s.Metrics.IncPless("verify", "validation_failed")
			return nil, &ValidationError{Fields: []FieldError{{Field: "code", Reason: "INVALID_FORMAT"}}}
		}
		hash, method = h, "otp"
	}
	hasIdem := false
	if _, err := uuid.Parse(in.RequestID); err == nil && in.RequestID != "" {
		hasIdem = true
		if s.Idem != nil {
			if v, found, _ := s.Idem.Get(ctx, in.RequestID); found {
				s.Metrics.ObservePlessDuration("verify", time.Since(start).Seconds())
				return plessReplayOutput(v), nil
			}
		}
	}

	rec, ferr := s.Store.FindAlive(ctx, hash)
	if ferr != nil {
		if errors.Is(ferr, auth.ErrPlessInvalid) || errors.Is(ferr, auth.ErrPlessBurned) {
			return s.invalid(ctx, method, start, "invalid")
		}
		s.Metrics.IncPless("verify", "error")
		return nil, auth.ErrInfra
	}

	// Defensa en profundidad: comparación en tiempo constante aunque el
	// lookup ya filtró (SEC-01). Solo el hash del método invocado.
	var stored string
	if method == "link" {
		stored = rec.TokenHash
	} else {
		stored = rec.OTPHash
	}
	if stored == "" || subtle.ConstantTimeCompare([]byte(stored), []byte(hash)) != 1 {
		if burned, _ := s.Store.IncrementAttempts(ctx, hash); burned {
			s.Metrics.IncPless("verify", "burned")
		}
		return s.invalid(ctx, method, start, "invalid")
	}

	consumeCtx := auth.NewPlessContext(in.IP, in.UserAgent)
	risk := auth.RiskOf(rec.Ctx, consumeCtx)
	consumed, cerr := s.Store.ConsumeTx(ctx, rec.UserID, hash, method, risk, consumeCtx.IPHash24, consumeCtx.UAHash)
	if cerr != nil {
		if errors.Is(cerr, auth.ErrPlessInvalid) || errors.Is(cerr, auth.ErrPlessBurned) {
			return s.invalid(ctx, method, start, "invalid")
		}
		s.Metrics.IncPless("verify", "error")
		return nil, auth.ErrInfra
	}
	if risk == "high" {
		s.Metrics.IncMismatch("high")
	}
	_ = s.Audit.Log(ctx, "passwordless.verify", map[string]string{
		"action": "passwordless.verify", "user_id": consumed.UserID,
		"result": "success", "method": method, "risk": risk,
	})

	// Bifurca MFA (igual login): con MFA → 202 pre-token (sin sesión).
	if consumed.MFAEnabled {
		token, challengeID, expiresIn, merr := s.MFA.IssueChallenge(ctx, consumed.UserID)
		if merr != nil {
			s.Metrics.IncPless("verify", "error")
			return nil, fmt.Errorf("mfa challenge: %w", auth.ErrInfra)
		}
		if s.Challenges != nil {
			if rerr := s.Challenges.Register(ctx, challengeID, consumed.UserID); rerr != nil {
				s.Metrics.IncPless("verify", "error")
				return nil, fmt.Errorf("challenge store: %w", auth.ErrInfra)
			}
		}
		s.Metrics.IncPless("verify", "mfa_required")
		s.Metrics.ObservePlessDuration("verify", time.Since(start).Seconds())
		if hasIdem {
			s.putPlessVerifyIdem(ctx, in.RequestID, "mfa_required")
		}
		return &PlessVerifyOutput{Status: "mfa_required", Challenge: &MFAChallengeData{
			Token: token, Methods: []string{"totp"}, ExpiresIn: expiresIn,
		}, Method: method, Risk: risk}, nil
	}

	pair, serr := s.Sessions.Issue(ctx, auth.SessionRequest{
		UserID: consumed.UserID, Method: auth.MethodPasswordlessEmail,
		AMR: []auth.AMR{auth.AMROTPEmail}, AuthTime: time.Now().UTC(),
		Device: auth.Device{IPHash: consumeCtx.IPHash24, UAHash: consumeCtx.UAHash},
		Roles:  []string{"user"},
	})
	if serr != nil {
		s.Metrics.IncPless("verify", "error")
		return nil, fmt.Errorf("issue session: %w", auth.ErrInfra)
	}
	s.Metrics.IncPless("verify", "success")
	s.Metrics.ObservePlessDuration("verify", time.Since(start).Seconds())
	if hasIdem {
		s.putPlessVerifyIdem(ctx, in.RequestID, "active")
	}
	return &PlessVerifyOutput{Status: "active", Session: &SessionData{
		AccessToken: pair.AccessJWT, RefreshTokenID: pair.RefreshPlain,
		ExpiresAt: pair.ExpiresAt.Unix(), SID: pair.SID,
	}, Method: method, Risk: risk}, nil
}

// invalid aplica delay uniforme 40-80ms + métrica opaca (anti-oráculo).
func (s *PasswordlessVerifyService) invalid(ctx context.Context, method string, start time.Time, result string) (*PlessVerifyOutput, error) {
	s.Sleep(plessVerifyJitter())
	_ = s.Audit.Log(ctx, "passwordless.verify", map[string]string{
		"action": "passwordless.verify", "result": result, "method": method,
	})
	s.Metrics.IncPless("verify", result)
	s.Metrics.ObservePlessDuration("verify", time.Since(start).Seconds())
	return nil, auth.ErrPlessInvalid
}

func (s *PasswordlessVerifyService) putPlessVerifyIdem(ctx context.Context, requestID, status string) {
	if s.Idem == nil || requestID == "" {
		return
	}
	_ = s.Idem.Put(ctx, requestID, status, 24*time.Hour)
}

// plessReplayOutput reconstruye respuesta idempotente (sin side-effects,
// sin re-emitir secretos ni sesión — RN-03).
func plessReplayOutput(status string) *PlessVerifyOutput {
	return &PlessVerifyOutput{Status: status}
}
