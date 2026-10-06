package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/shared"
	"auth-identity-service/internal/domain/user"

	"github.com/google/uuid"
)

// PwdResetStartInput entrada start (anónimo, sin sesión).
type PwdResetStartInput struct {
	EmailRaw  string
	RequestID string
	IP        string
	UserAgent string
}

// PwdResetStartOutput respuesta genérica (el handler siempre 202).
type PwdResetStartOutput struct {
	Status string // siempre "if_exists_sent"
}

// PasswordResetStartService orquesta POST /password/reset/start (CU-CRED-01).
// SIEMPRE genérico: elegible, hint federado o nada → mismo output.
// Solo forma malformada → 400; IP-rate → 429 (handler/middleware).
type PasswordResetStartService struct {
	Store   auth.PasswordResetStore
	Issuer  VerificationPairIssuer
	Idem    shared.IdempotencyStore
	Audit   shared.AuditLogger
	Metrics PwdResetMetricsPort
	Tracer  TracerPort
	Sleep   func(time.Duration)
}

func NewPasswordResetStartService(
	store auth.PasswordResetStore,
	issuer VerificationPairIssuer,
	idem shared.IdempotencyStore,
	audit shared.AuditLogger,
	metrics PwdResetMetricsPort,
	tracer TracerPort,
) *PasswordResetStartService {
	if metrics == nil {
		metrics = NoopPwdResetMetrics{}
	}
	if tracer == nil {
		tracer = NoopTracer{}
	}
	if audit == nil {
		audit = NoopAudit{}
	}
	return &PasswordResetStartService{
		Store: store, Issuer: issuer, Idem: idem, Audit: audit,
		Metrics: metrics, Tracer: tracer, Sleep: time.Sleep,
	}
}

const pwdResetStartQueued = "if_exists_sent"

func pwdResetStartJitter() time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(41))
	if err != nil {
		return 60 * time.Millisecond
	}
	return 60*time.Millisecond + time.Duration(n.Int64())*time.Millisecond
}

// Execute implementa §3 pasos 1-5: forma→rate→lookup→dummy→(issue|hint|noop)→202.
func (s *PasswordResetStartService) Execute(ctx context.Context, in PwdResetStartInput) (*PwdResetStartOutput, error) {
	start := time.Now()
	ctx, span := s.Tracer.Start(ctx, "UseCase.PasswordResetStart")
	defer span.End()
	out := &PwdResetStartOutput{Status: pwdResetStartQueued}

	normalized, _, nerr := user.Normalize(in.EmailRaw)
	if nerr != nil {
		s.Metrics.IncReset("start", "validation_failed")
		return nil, &ValidationError{Fields: []FieldError{{Field: "email", Reason: "INVALID_FORMAT"}}}
	}
	hasIdem := false
	if _, err := uuid.Parse(in.RequestID); err == nil && in.RequestID != "" {
		hasIdem = true
		if s.Idem != nil {
			if _, found, _ := s.Idem.Get(ctx, in.RequestID); found {
				s.Metrics.ObserveResetDuration("start", time.Since(start).Seconds())
				return out, nil
			}
		}
	}

	uid, eligible, hint, lerr := s.Store.EligibleForReset(ctx, normalized)
	if lerr != nil {
		s.Metrics.IncReset("start", "error")
		return nil, auth.ErrInfra
	}
	emailHash := pwdResetEmailHash(normalized)

	// Camino homogéneo SIEMPRE: trabajo constante + jitter 60-100ms.
	var dummy [40]byte
	_, _ = rand.Read(dummy[:])
	s.Sleep(pwdResetStartJitter())

	quotaKey := uid
	if (!eligible && !hint) || quotaKey == "" {
		quotaKey = "anon:" + emailHash
	}
	allowed, _, qerr := s.Store.QuotaCheck(ctx, quotaKey)
	if qerr != nil || !allowed {
		_ = s.Audit.Log(ctx, "password.reset_start", map[string]string{
			"action": "password.reset_start", "email_hash": emailHash, "result": "throttled",
		})
		s.Metrics.IncReset("start", "throttled")
		if hasIdem {
			s.putPwdResetIdem(ctx, in.RequestID)
		}
		s.Metrics.ObserveResetDuration("start", time.Since(start).Seconds())
		return out, nil
	}

	switch {
	case eligible:
		// Solo link 32B (sin OTP débil, Q3): se descarta el OTP del par.
		tokenPlain, tokenHash, _, _, gerr := s.Issuer.GeneratePair()
		if gerr != nil {
			s.Metrics.IncReset("start", "error")
			return nil, auth.ErrInfra
		}
		now := time.Now().UTC()
		rec := &auth.PasswordResetRecord{
			UserID: uid, TokenHash: tokenHash,
			ExpiresAt: now.Add(auth.PwdResetTTL), Attempts: 0,
			Ctx:        auth.NewPlessContext(in.IP, in.UserAgent),
			TokenPlain: tokenPlain,
		}
		if rerr := s.Store.Issue(ctx, rec); rerr != nil {
			s.Metrics.IncReset("start", "error")
			return nil, auth.ErrInfra
		}
		_ = s.Audit.Log(ctx, "password.reset_start", map[string]string{
			"action": "password.reset_start", "email_hash": emailHash,
			"user_id": uid, "result": "sent",
		})
		s.Metrics.IncReset("start", "sent")
	case hint:
		if herr := s.Store.IssueHint(ctx, uid, normalized); herr != nil {
			s.Metrics.IncReset("start", "error")
			return nil, auth.ErrInfra
		}
		_ = s.Audit.Log(ctx, "password.reset_start", map[string]string{
			"action": "password.reset_start", "email_hash": emailHash,
			"user_id": uid, "result": "federated_hint",
		})
		s.Metrics.IncReset("start", "federated_hint")
	default:
		_ = s.Audit.Log(ctx, "password.reset_start", map[string]string{
			"action": "password.reset_start", "email_hash": emailHash, "result": "not_sent",
		})
		s.Metrics.IncReset("start", "not_eligible")
	}
	if hasIdem {
		s.putPwdResetIdem(ctx, in.RequestID)
	}
	s.Metrics.ObserveResetDuration("start", time.Since(start).Seconds())
	return out, nil
}

func (s *PasswordResetStartService) putPwdResetIdem(ctx context.Context, requestID string) {
	if s.Idem == nil || requestID == "" {
		return
	}
	_ = s.Idem.Put(ctx, requestID, pwdResetStartQueued, 24*time.Hour)
}

func pwdResetEmailHash(normalized string) string {
	h := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(h[:])
}
