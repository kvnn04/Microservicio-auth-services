package service

import (
	"context"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/shared"
	"auth-identity-service/internal/domain/user"

	"github.com/google/uuid"
)

// ResendInput: email crudo + idempotencia. Respuesta siempre genérica.
type ResendInput struct {
	EmailRaw  string
	RequestID string
	IP        string
	UserAgent string
}

// ResendOutput: status fijo anti-enumeración.
type ResendOutput struct {
	Status string // siempre "if_exists_verification_sent"
}

// ResendService orquesta POST /resend-verification (CU-REG-02 §4.5).
type ResendService struct {
	Users   user.UserRepository
	Store   auth.VerificationStore
	Issuer  VerificationPairIssuer
	Idem    shared.IdempotencyStore
	Audit   shared.AuditLogger
	Metrics VerifyMetricsPort
	Tracer  TracerPort
}

func NewResendService(
	users user.UserRepository,
	store auth.VerificationStore,
	issuer VerificationPairIssuer,
	idem shared.IdempotencyStore,
	audit shared.AuditLogger,
	metrics VerifyMetricsPort,
	tracer TracerPort,
) *ResendService {
	if metrics == nil {
		metrics = NoopVerifyMetrics{}
	}
	if tracer == nil {
		tracer = NoopTracer{}
	}
	if audit == nil {
		audit = NoopAudit{}
	}
	return &ResendService{
		Users: users, Store: store, Issuer: issuer, Idem: idem,
		Audit: audit, Metrics: metrics, Tracer: tracer,
	}
}

const resendQueued = "if_exists_verification_sent"

// Execute: SIEMPRE 202 genérico exista o no, ACTIVE o PENDING, cooldown o cuota.
func (s *ResendService) Execute(ctx context.Context, in ResendInput) (*ResendOutput, error) {
	ctx, span := s.Tracer.Start(ctx, "UseCase.ResendVerification")
	defer span.End()
	out := &ResendOutput{Status: resendQueued}

	if _, err := uuid.Parse(in.RequestID); err != nil {
		// Sin RequestID válido no hay idempotencia: igualmente genérico 202.
		return out, nil
	}
	if s.Idem != nil {
		if _, found, _ := s.Idem.Get(ctx, in.RequestID); found {
			return out, nil
		}
	}

	normalized, _, nerr := user.Normalize(in.EmailRaw)
	if nerr != nil {
		// Email malformado → genérico sin revelar (no-op).
		s.putIdem(ctx, in.RequestID)
		return out, nil
	}
	existing, ferr := s.Users.FindByEmailNormalized(ctx, normalized)
	if ferr != nil || existing == nil || existing.Status != user.StatusPendingVerification {
		// Inexistente o no-PENDING (ACTIVE/LOCKED/...) → genérico sin enviar.
		s.Metrics.IncResend("throttled")
		s.putIdem(ctx, in.RequestID)
		return out, nil
	}

	allowed, _, qerr := s.Store.ResendQuotaCheck(ctx, existing.ID)
	if qerr != nil || !allowed {
		_ = s.Audit.Log(ctx, "user.verification_resent", map[string]string{
			"result": "throttled", "user_id": existing.ID,
		})
		s.Metrics.IncResend("throttled")
		s.putIdem(ctx, in.RequestID)
		return out, nil
	}

	tokenPlain, tokenHash, otpPlain, otpHash, gerr := s.Issuer.GeneratePair()
	if gerr != nil {
		// Error interno: igualmente 202 genérico (outbox pendiente se reintenta).
		// El contrato exige 202 aun con Kafka caído; con fallo de RNG retornamos
		// genérico sin enviar y métrica de error interna.
		s.Metrics.IncResend("throttled")
		s.putIdem(ctx, in.RequestID)
		return out, nil
	}
	now := time.Now().UTC()
	rec := &auth.VerificationRecord{
		UserID: existing.ID, TokenHash: tokenHash, OTPHash: otpHash,
		ExpiresAt: now.Add(auth.VerifyTTL), Attempts: 0,
		TokenPlain: tokenPlain, OTPPlain: otpPlain,
	}
	if rerr := s.Store.Register(ctx, rec); rerr != nil {
		s.Metrics.IncResend("throttled")
		s.putIdem(ctx, in.RequestID)
		return out, nil
	}
	// Evento dirigido al mailer (único con email plano, canal interno).
	_ = s.Audit.Log(ctx, "user.verification_resent", map[string]string{
		"result": "resent", "user_id": existing.ID, "method": "pair",
	})
	s.Metrics.IncResend("queued")
	s.putIdem(ctx, in.RequestID)
	return out, nil
}

func (s *ResendService) putIdem(ctx context.Context, requestID string) {
	if s.Idem == nil {
		return
	}
	_ = s.Idem.Put(ctx, requestID, resendQueued, 24*time.Hour)
}
