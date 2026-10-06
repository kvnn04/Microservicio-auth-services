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

// PlessStartInput entrada start (anónimo, sin sesión).
type PlessStartInput struct {
	EmailRaw  string
	RequestID string
	IP        string
	UserAgent string
}

// PlessStartOutput respuesta genérica (el handler siempre 202).
type PlessStartOutput struct {
	Status string // siempre "if_exists_sent"
}

// PasswordlessStartService orquesta POST /passwordless/start (CU-AUTH-05).
// SIEMPRE genérico: elegible o no, throttled o no → mismo output (anti-oráculo).
// Solo forma malformada → 400; IP-rate → 429 (los decide el handler/middleware).
type PasswordlessStartService struct {
	Store   auth.PasswordlessStore
	Issuer  VerificationPairIssuer
	Idem    shared.IdempotencyStore
	Audit   shared.AuditLogger
	Metrics PlessMetricsPort
	Tracer  TracerPort
	Sleep   func(time.Duration)
}

func NewPasswordlessStartService(
	store auth.PasswordlessStore,
	issuer VerificationPairIssuer,
	idem shared.IdempotencyStore,
	audit shared.AuditLogger,
	metrics PlessMetricsPort,
	tracer TracerPort,
) *PasswordlessStartService {
	if metrics == nil {
		metrics = NoopPlessMetrics{}
	}
	if tracer == nil {
		tracer = NoopTracer{}
	}
	if audit == nil {
		audit = NoopAudit{}
	}
	return &PasswordlessStartService{
		Store: store, Issuer: issuer, Idem: idem, Audit: audit,
		Metrics: metrics, Tracer: tracer, Sleep: time.Sleep,
	}
}

const plessStartQueued = "if_exists_sent"

func plessStartJitter() time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(41))
	if err != nil {
		return 60 * time.Millisecond
	}
	return 60*time.Millisecond + time.Duration(n.Int64())*time.Millisecond
}

func plessEmailHash(normalized string) string {
	h := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(h[:])
}

// Execute implementa el flujo §3 pasos 1-5: forma→rate→lookup→dummy→(issue|noop)→202.
func (s *PasswordlessStartService) Execute(ctx context.Context, in PlessStartInput) (*PlessStartOutput, error) {
	start := time.Now()
	ctx, span := s.Tracer.Start(ctx, "UseCase.PasswordlessStart")
	defer span.End()
	out := &PlessStartOutput{Status: plessStartQueued}

	// 1. Forma rápida (malforma → 400, sin contadores).
	normalized, _, nerr := user.Normalize(in.EmailRaw)
	if nerr != nil {
		s.Metrics.IncPless("start", "validation_failed")
		return nil, &ValidationError{Fields: []FieldError{{Field: "email", Reason: "INVALID_FORMAT"}}}
	}
	hasIdem := false
	if _, err := uuid.Parse(in.RequestID); err == nil && in.RequestID != "" {
		hasIdem = true
		if s.Idem != nil {
			if _, found, _ := s.Idem.Get(ctx, in.RequestID); found {
				s.Metrics.ObservePlessDuration("start", time.Since(start).Seconds())
				return out, nil
			}
		}
	}

	// 2. Lookup elegibilidad (guarda bool, no ramifica respuesta ni tiempos).
	uid, _, eligible, lerr := s.Store.Eligible(ctx, normalized)
	if lerr != nil {
		s.Metrics.IncPless("start", "error")
		return nil, auth.ErrInfra
	}
	emailHash := plessEmailHash(normalized)

	// 3. Camino homogéneo SIEMPRE: trabajo constante + jitter 60-100ms.
	// (Más ligero que Argon2 —aquí no hay hash que igualar— pero indistinguible.)
	var dummy [40]byte
	_, _ = rand.Read(dummy[:])
	s.Sleep(plessStartJitter())

	// 4. Quota solo si elegible (por uid; si no, por email_hash para no distinguir).
	quotaKey := uid
	if !eligible || quotaKey == "" {
		quotaKey = "anon:" + emailHash
	}
	allowed, _, qerr := s.Store.QuotaCheck(ctx, quotaKey)
	if qerr != nil || !allowed {
		_ = s.Audit.Log(ctx, "passwordless.start", map[string]string{
			"action": "passwordless.start", "email_hash": emailHash,
			"result": "throttled",
		})
		s.Metrics.IncPless("start", "throttled")
		if hasIdem {
			s.putPlessIdem(ctx, in.RequestID)
		}
		s.Metrics.ObservePlessDuration("start", time.Since(start).Seconds())
		return out, nil
	}
	if !eligible {
		_ = s.Audit.Log(ctx, "passwordless.start", map[string]string{
			"action": "passwordless.start", "email_hash": emailHash,
			"result": "not_sent",
		})
		s.Metrics.IncPless("start", "not_eligible")
		if hasIdem {
			s.putPlessIdem(ctx, in.RequestID)
		}
		s.Metrics.ObservePlessDuration("start", time.Since(start).Seconds())
		return out, nil
	}

	// 5. Elegible + quota libre → emite par + persiste (supersede + outbox + email).
	tokenPlain, tokenHash, otpPlain, otpHash, gerr := s.Issuer.GeneratePair()
	if gerr != nil {
		s.Metrics.IncPless("start", "error")
		return nil, auth.ErrInfra
	}
	now := time.Now().UTC()
	rec := &auth.PasswordlessRecord{
		UserID: uid, TokenHash: tokenHash, OTPHash: otpHash,
		ExpiresAt: now.Add(auth.PlessTTL), Attempts: 0,
		Ctx:        auth.NewPlessContext(in.IP, in.UserAgent),
		TokenPlain: tokenPlain, OTPPlain: otpPlain,
	}
	if rerr := s.Store.Issue(ctx, rec); rerr != nil {
		s.Metrics.IncPless("start", "error")
		return nil, auth.ErrInfra
	}
	_ = s.Audit.Log(ctx, "passwordless.start", map[string]string{
		"action": "passwordless.start", "email_hash": emailHash, "user_id": uid,
		"result": "sent",
	})
	s.Metrics.IncPless("start", "sent")
	if hasIdem {
		s.putPlessIdem(ctx, in.RequestID)
	}
	s.Metrics.ObservePlessDuration("start", time.Since(start).Seconds())
	return out, nil
}

func (s *PasswordlessStartService) putPlessIdem(ctx context.Context, requestID string) {
	if s.Idem == nil || requestID == "" {
		return
	}
	_ = s.Idem.Put(ctx, requestID, plessStartQueued, 24*time.Hour)
}
