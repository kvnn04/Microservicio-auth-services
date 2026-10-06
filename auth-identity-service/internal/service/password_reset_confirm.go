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

// PwdResetConfirmInput entrada confirm (el token reset es la auth;
// si trae Bearer se ignora).
type PwdResetConfirmInput struct {
	Token       string
	NewPassword string
	Confirm     string // opcional: si viene debe coincidir
	HasConfirm  bool
	RequestID   string
	IP          string
	UserAgent   string
}

// PwdResetConfirmOutput cambio aplicado (sin auto-login: debe POST /login).
type PwdResetConfirmOutput struct {
	Status string // siempre "password_changed"
}

// PasswordResetConfirmService orquesta POST /password/reset/confirm.
// Token inválido → 400 opaco + delay; policy/reused → 400 con detalle
// (sin quemar token); éxito → corte global de sesiones sin Issue.
type PasswordResetConfirmService struct {
	Store     auth.PasswordResetStore
	Hasher    auth.PasswordHasher
	Breach    auth.BreachChecker
	Idem      shared.IdempotencyStore
	Audit     shared.AuditLogger
	Metrics   PwdResetMetricsPort
	Tracer    TracerPort
	Sleep     func(time.Duration)
	localDeny map[string]struct{}
}

func NewPasswordResetConfirmService(
	store auth.PasswordResetStore,
	hasher auth.PasswordHasher,
	breach auth.BreachChecker,
	idem shared.IdempotencyStore,
	audit shared.AuditLogger,
	metrics PwdResetMetricsPort,
	tracer TracerPort,
) *PasswordResetConfirmService {
	if metrics == nil {
		metrics = NoopPwdResetMetrics{}
	}
	if tracer == nil {
		tracer = NoopTracer{}
	}
	if audit == nil {
		audit = NoopAudit{}
	}
	return &PasswordResetConfirmService{
		Store: store, Hasher: hasher, Breach: breach, Idem: idem,
		Audit: audit, Metrics: metrics, Tracer: tracer, Sleep: time.Sleep,
		localDeny: defaultDenyList(),
	}
}

const pwdResetChanged = "password_changed"

func pwdResetConfirmJitter() time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(41))
	if err != nil {
		return 40 * time.Millisecond
	}
	return 40*time.Millisecond + time.Duration(n.Int64())*time.Millisecond
}

// Execute implementa §3 pasos 7-8: forma+policy→rate→find→reused→hash→Tx→200.
func (s *PasswordResetConfirmService) Execute(ctx context.Context, in PwdResetConfirmInput) (*PwdResetConfirmOutput, error) {
	start := time.Now()
	ctx, span := s.Tracer.Start(ctx, "UseCase.PasswordResetConfirm")
	defer span.End()

	hash, err := auth.ParseResetToken(in.Token)
	if err != nil {
		s.Metrics.IncReset("confirm", "validation_failed")
		return nil, &ValidationError{Fields: []FieldError{{Field: "token", Reason: "INVALID_FORMAT"}}}
	}
	if in.NewPassword == "" {
		s.Metrics.IncReset("confirm", "validation_failed")
		return nil, &ValidationError{Fields: []FieldError{{Field: "new_password", Reason: "REQUIRED"}}}
	}
	if in.HasConfirm && in.Confirm != in.NewPassword {
		s.Metrics.IncReset("confirm", "validation_failed")
		return nil, &ValidationError{Fields: []FieldError{{Field: "new_password_confirm", Reason: "MISMATCH"}}}
	}

	// Idempotencia 24h antes del lookup: replay del RequestID que ya
	// consumió → mismo 200 sin re-validar (el token ya está quemado).
	hasIdem := false
	if _, err := uuid.Parse(in.RequestID); err == nil && in.RequestID != "" {
		hasIdem = true
		if s.Idem != nil {
			if v, found, _ := s.Idem.Get(ctx, in.RequestID); found && v == pwdResetChanged {
				s.Metrics.IncReset("confirm", "replayed")
				s.Metrics.ObserveResetDuration("confirm", time.Since(start).Seconds())
				return &PwdResetConfirmOutput{Status: pwdResetChanged}, nil
			}
		}
	}

	rec, u, ferr := s.Store.FindAlive(ctx, hash)
	if ferr != nil {
		if errors.Is(ferr, auth.ErrPwdResetInvalid) || errors.Is(ferr, auth.ErrPwdResetBurned) {
			_, _ = s.Store.IncrementAttempts(ctx, hash)
			return s.invalid(ctx, start, "invalid")
		}
		s.Metrics.IncReset("confirm", "error")
		return nil, auth.ErrInfra
	}

	// Defensa en profundidad: comparación en tiempo constante aunque el
	// lookup ya filtró (SEC-01).
	if subtle.ConstantTimeCompare([]byte(rec.TokenHash), []byte(hash)) != 1 {
		_, _ = s.Store.IncrementAttempts(ctx, hash)
		return s.invalid(ctx, start, "invalid")
	}

	// Policy CU-REG-01 (con parte local real) + HIBP. Falla → 400 con
	// detalle SIN quemar el token (permite corregir la clave).
	if pwErr := auth.ValidateSyntax(in.NewPassword, auth.LocalPart(u.EmailNormalized)); pwErr != nil {
		s.Metrics.IncReset("confirm", "policy_failed")
		s.Metrics.ObserveResetDuration("confirm", time.Since(start).Seconds())
		return nil, &ValidationError{Fields: []FieldError{{Field: "new_password", Reason: mapPasswordReason(pwErr)}}}
	}
	if perr := s.checkBreach(ctx, in.NewPassword); perr != nil {
		s.Metrics.IncReset("confirm", "policy_failed")
		s.Metrics.ObserveResetDuration("confirm", time.Since(start).Seconds())
		return nil, perr
	}

	// ≠ actual: Verify true → REUSED (cuenta abuso, sin quemar este intento).
	same, verr := s.Hasher.Verify(ctx, in.NewPassword, u.PasswordHash)
	if verr == nil && same {
		_, _ = s.Store.IncrementAttempts(ctx, hash)
		_ = s.Audit.Log(ctx, "password.reset_confirm", map[string]string{
			"action": "password.reset_confirm", "user_id": u.ID, "result": "reused",
		})
		s.Metrics.IncReset("confirm", "reused")
		s.Metrics.ObserveResetDuration("confirm", time.Since(start).Seconds())
		return nil, auth.ErrPasswordReused
	}

	newHash, herr := s.Hasher.Hash(ctx, in.NewPassword)
	if herr != nil {
		s.Metrics.IncReset("confirm", "error")
		return nil, fmt.Errorf("hash password: %w", auth.ErrInfra)
	}
	consumeCtx := auth.NewPlessContext(in.IP, in.UserAgent)
	risk := auth.RiskOf(rec.Ctx, consumeCtx)
	if cerr := s.Store.ConsumeTx(ctx, u.ID, hash, newHash, risk, consumeCtx.IPHash24, consumeCtx.UAHash, in.RequestID); cerr != nil {
		if errors.Is(cerr, auth.ErrPwdResetInvalid) || errors.Is(cerr, auth.ErrPwdResetBurned) {
			_, _ = s.Store.IncrementAttempts(ctx, hash)
			return s.invalid(ctx, start, "invalid")
		}
		s.Metrics.IncReset("confirm", "error")
		return nil, auth.ErrInfra
	}
	if risk == "high" {
		s.Metrics.IncMismatch("high")
	}
	_ = s.Audit.Log(ctx, "password.reset_confirm", map[string]string{
		"action": "password.reset_confirm", "user_id": u.ID,
		"result": "success", "risk": risk,
	})
	s.Metrics.IncReset("confirm", "success")
	s.Metrics.ObserveResetDuration("confirm", time.Since(start).Seconds())
	if hasIdem {
		if s.Idem != nil {
			_ = s.Idem.Put(ctx, in.RequestID, pwdResetChanged, 24*time.Hour)
		}
	}
	return &PwdResetConfirmOutput{Status: pwdResetChanged}, nil
}

// checkBreach aplica HIBP con fallback a lista local (igual registro).
// Retorna ValidationError COMPROMISED o nil.
func (s *PasswordResetConfirmService) checkBreach(ctx context.Context, password string) error {
	if s.Breach == nil {
		return nil
	}
	compromised, berr := s.Breach.IsCompromised(ctx, password)
	if berr != nil {
		s.Metrics.IncHibpFallback()
		if _, denied := s.localDeny[password]; denied {
			return &ValidationError{Fields: []FieldError{{Field: "new_password", Reason: "COMPROMISED"}}}
		}
		return nil
	}
	if compromised {
		return &ValidationError{Fields: []FieldError{{Field: "new_password", Reason: "COMPROMISED"}}}
	}
	return nil
}

// invalid aplica delay uniforme 40-80ms + 400 opaco (anti-oráculo).
func (s *PasswordResetConfirmService) invalid(ctx context.Context, start time.Time, result string) (*PwdResetConfirmOutput, error) {
	s.Sleep(pwdResetConfirmJitter())
	_ = s.Audit.Log(ctx, "password.reset_confirm", map[string]string{
		"action": "password.reset_confirm", "result": result,
	})
	s.Metrics.IncReset("confirm", result)
	s.Metrics.ObserveResetDuration("confirm", time.Since(start).Seconds())
	return nil, auth.ErrPwdResetInvalid
}
