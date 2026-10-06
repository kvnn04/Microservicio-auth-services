package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"math/big"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/shared"
	"auth-identity-service/internal/domain/user"

	"github.com/google/uuid"
)

// EmailChangeConfirmInput entrada confirm (el link es la auth;
// Bearer opcional ligado al requester).
type EmailChangeConfirmInput struct {
	Token         string
	RequestID     string
	BearerUserID  string
	HasBearer     bool
}

// EmailChangeConfirmOutput cambio aplicado (sin sesión: re-login).
type EmailChangeConfirmOutput struct {
	Status string // siempre "email_changed"
	Masked string
}

// EmailChangeConfirmService orquesta POST /email/change/confirm (CU-CRED-03).
// Token opaco + bearer-check + re-UNIQUE en Tx + corte global + relogin.
type EmailChangeConfirmService struct {
	Store   user.EmailChangeStore
	Idem    shared.IdempotencyStore
	Audit   shared.AuditLogger
	Metrics EmailChangeMetricsPort
	Tracer  TracerPort
	Sleep   func(time.Duration)
}

func NewEmailChangeConfirmService(
	store user.EmailChangeStore,
	idem shared.IdempotencyStore,
	audit shared.AuditLogger,
	metrics EmailChangeMetricsPort,
	tracer TracerPort,
) *EmailChangeConfirmService {
	if metrics == nil {
		metrics = NoopEmailChangeMetrics{}
	}
	if tracer == nil {
		tracer = NoopTracer{}
	}
	if audit == nil {
		audit = NoopAudit{}
	}
	return &EmailChangeConfirmService{
		Store: store, Idem: idem, Audit: audit,
		Metrics: metrics, Tracer: tracer, Sleep: time.Sleep,
	}
}

const emailChanged = "email_changed"

func emailChangeJitter() time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(41))
	if err != nil {
		return 40 * time.Millisecond
	}
	return 40*time.Millisecond + time.Duration(n.Int64())*time.Millisecond
}

// Execute implementa §3 pasos 6-7: forma→find→bearer→Tx→200.
func (s *EmailChangeConfirmService) Execute(ctx context.Context, in EmailChangeConfirmInput) (*EmailChangeConfirmOutput, error) {
	start := time.Now()
	ctx, span := s.Tracer.Start(ctx, "UseCase.EmailChangeConfirm")
	defer span.End()

	hash, err := user.ParseEmailChangeToken(in.Token)
	if err != nil {
		s.Metrics.IncEmailChange("confirm", "validation_failed")
		return nil, &ValidationError{Fields: []FieldError{{Field: "token", Reason: "INVALID_FORMAT"}}}
	}
	hasIdem := false
	if _, err := uuid.Parse(in.RequestID); err == nil && in.RequestID != "" {
		hasIdem = true
		if s.Idem != nil {
			if v, found, _ := s.Idem.Get(ctx, in.RequestID); found {
				if masked, ok := splitMasked(v); ok {
					s.Metrics.IncEmailChange("confirm", "replayed")
					s.Metrics.ObserveEmailChangeDuration("confirm", time.Since(start).Seconds())
					return &EmailChangeConfirmOutput{Status: emailChanged, Masked: masked}, nil
				}
			}
		}
	}

	rec, ferr := s.Store.FindAlive(ctx, hash)
	if ferr != nil {
		if errors.Is(ferr, user.ErrEmailChangeInvalid) || errors.Is(ferr, user.ErrEmailChangeBurned) {
			_, _ = s.Store.IncrementAttempts(ctx, hash)
			return s.invalid(ctx, start, "invalid")
		}
		s.Metrics.IncEmailChange("confirm", "error")
		return nil, auth.ErrInfra
	}

	// Defensa en profundidad: comparación en tiempo constante aunque el
	// lookup ya filtró (SEC-01).
	if subtle.ConstantTimeCompare([]byte(rec.TokenHash), []byte(hash)) != 1 {
		_, _ = s.Store.IncrementAttempts(ctx, hash)
		return s.invalid(ctx, start, "invalid")
	}

	// Bearer ajeno al requester → 400 opaco (cuenta como abuso, §4.2).
	if in.HasBearer && in.BearerUserID != rec.RequesterID {
		_, _ = s.Store.IncrementAttempts(ctx, hash)
		return s.invalid(ctx, start, "user_mismatch")
	}

	requesterID, newNorm, cerr := s.Store.ConfirmTx(ctx, hash)
	if cerr != nil {
		switch {
		case errors.Is(cerr, user.ErrEmailAlreadyInUse):
			_ = s.Audit.Log(ctx, "email.change_confirm", map[string]string{
				"action": "email.change_confirm", "result": "taken",
			})
			s.Metrics.IncEmailChange("confirm", "taken")
			s.Metrics.ObserveEmailChangeDuration("confirm", time.Since(start).Seconds())
			return nil, user.ErrEmailAlreadyInUse
		case errors.Is(cerr, user.ErrEmailChangeInvalid) || errors.Is(cerr, user.ErrEmailChangeBurned):
			_, _ = s.Store.IncrementAttempts(ctx, hash)
			return s.invalid(ctx, start, "invalid")
		default:
			s.Metrics.IncEmailChange("confirm", "error")
			return nil, auth.ErrInfra
		}
	}
	masked := user.MaskEmail(newNorm)
	_ = s.Audit.Log(ctx, "email.change_confirm", map[string]string{
		"action": "email.change_confirm", "user_id": requesterID,
		"new_hash": sha256Hex(newNorm), "result": "success",
	})
	s.Metrics.IncEmailChange("confirm", "success")
	s.Metrics.ObserveEmailChangeDuration("confirm", time.Since(start).Seconds())
	if hasIdem && s.Idem != nil {
		_ = s.Idem.Put(ctx, in.RequestID, emailChanged+"\n"+masked, 24*time.Hour)
	}
	return &EmailChangeConfirmOutput{Status: emailChanged, Masked: masked}, nil
}

// invalid aplica delay uniforme 40-80ms + 400 opaco (anti-oráculo).
func (s *EmailChangeConfirmService) invalid(ctx context.Context, start time.Time, result string) (*EmailChangeConfirmOutput, error) {
	s.Sleep(emailChangeJitter())
	_ = s.Audit.Log(ctx, "email.change_confirm", map[string]string{
		"action": "email.change_confirm", "result": result,
	})
	s.Metrics.IncEmailChange("confirm", result)
	s.Metrics.ObserveEmailChangeDuration("confirm", time.Since(start).Seconds())
	return nil, user.ErrEmailChangeInvalid
}

// splitMasked recupera el masked idempotente ("status\nmasked").
func splitMasked(v string) (string, bool) {
	for i := 0; i < len(v); i++ {
		if v[i] == '\n' {
			if v[:i] == emailChanged && i+1 < len(v) {
				return v[i+1:], true
			}
			return "", false
		}
	}
	return "", false
}
