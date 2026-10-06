package service

import (
	"context"
	"fmt"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/shared"
	"auth-identity-service/internal/domain/user"

	"github.com/google/uuid"
)

// ThrottledError indica quota excedida con reintento (handler → 429 + Retry-After).
type ThrottledError struct {
	RetryAfter time.Duration
	Scope      string
}

func (e *ThrottledError) Error() string { return "send quota throttled" }

// EmailChangeStartInput entrada start (Bearer + Step-Up ya autenticados).
type EmailChangeStartInput struct {
	User        AuthUser
	StepUpToken string
	NewEmailRaw string
	RequestID   string
}

// EmailChangeStartOutput solicitud creada (link al nuevo + aviso al viejo).
type EmailChangeStartOutput struct {
	Status string // siempre "confirmation_sent"
	Masked string // new enmascarado
}

// EmailChangeStartService orquesta POST /email/change/start (CU-CRED-03).
// Guard Step-Up primero (fast-pass o token scopeado), luego norma,
// unicidad explícita 409, quotas y doble-mail. Sin auto-login.
type EmailChangeStartService struct {
	Users   user.UserRepository
	Store   user.EmailChangeStore
	StepUp  StepUpChecker
	Issuer  VerificationPairIssuer
	Idem    shared.IdempotencyStore
	Audit   shared.AuditLogger
	Metrics EmailChangeMetricsPort
	Tracer  TracerPort
}

func NewEmailChangeStartService(
	users user.UserRepository,
	store user.EmailChangeStore,
	stepUp StepUpChecker,
	issuer VerificationPairIssuer,
	idem shared.IdempotencyStore,
	audit shared.AuditLogger,
	metrics EmailChangeMetricsPort,
	tracer TracerPort,
) *EmailChangeStartService {
	if metrics == nil {
		metrics = NoopEmailChangeMetrics{}
	}
	if tracer == nil {
		tracer = NoopTracer{}
	}
	if audit == nil {
		audit = NoopAudit{}
	}
	return &EmailChangeStartService{
		Users: users, Store: store, StepUp: stepUp, Issuer: issuer,
		Idem: idem, Audit: audit, Metrics: metrics, Tracer: tracer,
	}
}

const emailChangeSent = "confirmation_sent"

// Execute implementa §3 pasos 1-5: Step-Up→norm→rate→unicidad→quotas→doble-mail.
func (s *EmailChangeStartService) Execute(ctx context.Context, in EmailChangeStartInput) (*EmailChangeStartOutput, error) {
	start := time.Now()
	ctx, span := s.Tracer.Start(ctx, "UseCase.EmailChangeStart")
	defer span.End()

	if _, err := uuid.Parse(in.RequestID); err != nil {
		s.Metrics.IncEmailChange("start", "validation_failed")
		return nil, &ValidationError{Fields: []FieldError{{Field: "request_id", Reason: "INVALID_FORMAT"}}}
	}

	// 1. Guard Step-Up mandatorio (fast-pass o token scopeado). Sin rate previo.
	if s.StepUp == nil {
		s.Metrics.IncEmailChange("start", "error")
		return nil, fmt.Errorf("step-up unavailable: %w", auth.ErrInfra)
	}
	if _, serr := s.StepUp.Check(ctx, in.User.ID, in.User.AuthTime, auth.ScopeChangeEmail, in.StepUpToken); serr != nil {
		_ = s.Audit.Log(ctx, "email.change_start", map[string]string{
			"action": "email.change_start", "user_id": in.User.ID, "result": "step_up_failed",
		})
		s.Metrics.IncEmailChange("start", "step_up_required")
		s.Metrics.ObserveEmailChangeDuration("start", time.Since(start).Seconds())
		return nil, serr
	}

	// 2. Normaliza + cuenta actual (para SAME_EMAIL y old_hash de audit).
	normalized, _, nerr := user.Normalize(in.NewEmailRaw)
	if nerr != nil {
		s.Metrics.IncEmailChange("start", "validation_failed")
		return nil, &ValidationError{Fields: []FieldError{{Field: "new_email", Reason: "INVALID_FORMAT"}}}
	}
	current, ferr := s.Users.FindByID(ctx, in.User.ID)
	if ferr != nil {
		s.Metrics.IncEmailChange("start", "error")
		return nil, fmt.Errorf("find user: %w", auth.ErrInfra)
	}
	if current.Status != user.StatusActive {
		s.Metrics.IncEmailChange("start", "error")
		return nil, auth.ErrAccountUnavailable
	}
	if normalized == current.EmailNormalized {
		s.Metrics.IncEmailChange("start", "same_email")
		s.Metrics.ObserveEmailChangeDuration("start", time.Since(start).Seconds())
		return nil, &ValidationError{Fields: []FieldError{{Field: "new_email", Reason: "SAME_EMAIL"}}}
	}

	// Idempotencia 60s: replay no re-emite (recalcula masked, puro).
	if s.Idem != nil {
		if _, found, _ := s.Idem.Get(ctx, in.RequestID); found {
			s.Metrics.IncEmailChange("start", "replayed")
			s.Metrics.ObserveEmailChangeDuration("start", time.Since(start).Seconds())
			return &EmailChangeStartOutput{Status: emailChangeSent, Masked: user.MaskEmail(normalized)}, nil
		}
	}

	// 3. Unicidad explícita (autenticado + rate + audit: no es oráculo anónimo).
	taken, terr := s.Store.Taken(ctx, normalized, current.ID)
	if terr != nil {
		s.Metrics.IncEmailChange("start", "error")
		return nil, fmt.Errorf("uniqueness: %w", auth.ErrInfra)
	}
	if taken {
		_ = s.Audit.Log(ctx, "email.change_start", map[string]string{
			"action": "email.change_start", "user_id": current.ID,
			"new_hash": sha256Hex(normalized), "result": "taken",
		})
		s.Metrics.IncEmailChange("start", "taken")
		s.Metrics.ObserveEmailChangeDuration("start", time.Since(start).Seconds())
		return nil, user.ErrEmailAlreadyInUse
	}

	// 4. Quotas de envío (throttled → 429 explícito, autenticado).
	allowed, retry, qerr := s.Store.QuotaCheck(ctx, current.ID)
	if qerr != nil || !allowed {
		_ = s.Audit.Log(ctx, "email.change_start", map[string]string{
			"action": "email.change_start", "user_id": current.ID, "result": "throttled",
		})
		s.Metrics.IncEmailChange("start", "throttled")
		s.Metrics.ObserveEmailChangeDuration("start", time.Since(start).Seconds())
		return nil, &ThrottledError{RetryAfter: retry, Scope: "start"}
	}

	tokenPlain, tokenHash, _, _, gerr := s.Issuer.GeneratePair()
	if gerr != nil {
		s.Metrics.IncEmailChange("start", "error")
		return nil, fmt.Errorf("pair: %w", auth.ErrInfra)
	}
	rec := &user.EmailChangeRecord{
		RequesterID: current.ID, TokenHash: tokenHash,
		NewNormalized: normalized, NewOriginal: in.NewEmailRaw,
		ExpiresAt: time.Now().UTC().Add(user.EmailChangeTTL),
		TokenPlain: tokenPlain,
	}
	if rerr := s.Store.Issue(ctx, rec); rerr != nil {
		s.Metrics.IncEmailChange("start", "error")
		return nil, fmt.Errorf("issue: %w", auth.ErrInfra)
	}
	_ = s.Audit.Log(ctx, "email.change_start", map[string]string{
		"action": "email.change_start", "user_id": current.ID,
		"old_hash": sha256Hex(current.EmailNormalized),
		"new_hash": sha256Hex(normalized), "result": "sent",
	})
	s.Metrics.IncEmailChange("start", "sent")
	s.Metrics.ObserveEmailChangeDuration("start", time.Since(start).Seconds())
	if s.Idem != nil {
		_ = s.Idem.Put(ctx, in.RequestID, emailChangeSent, 60*time.Second)
	}
	return &EmailChangeStartOutput{Status: emailChangeSent, Masked: user.MaskEmail(normalized)}, nil
}
