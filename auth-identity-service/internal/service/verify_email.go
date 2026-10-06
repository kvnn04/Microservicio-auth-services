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
	"auth-identity-service/internal/domain/user"

	"github.com/google/uuid"
)

// VerifyMetricsPort telemetría CU-REG-02 (T-05). Sin SDK directo (DIP).
type VerifyMetricsPort interface {
	IncVerification(result, method string)
	ObserveVerificationDuration(seconds float64)
	IncResend(outcome string)
	IncAttemptsBurned()
	IncRedisFallback(reason string)
}

// NoopVerifyMetrics default sin telemetría.
type NoopVerifyMetrics struct{}

func (NoopVerifyMetrics) IncVerification(string, string)      {}
func (NoopVerifyMetrics) ObserveVerificationDuration(float64) {}
func (NoopVerifyMetrics) IncResend(string)                    {}
func (NoopVerifyMetrics) IncAttemptsBurned()                  {}
func (NoopVerifyMetrics) IncRedisFallback(string)             {}

// VerificationPairIssuer genera el par link+OTP (solo hashes se persisten).
type VerificationPairIssuer interface {
	GeneratePair() (tokenPlain, tokenHash, otpPlain, otpHash string, err error)
}

// VerifyEmailInput: exactamente uno de Token/Code con raw sin normalizar.
type VerifyEmailInput struct {
	Token     string
	Code      string
	RequestID string
	IP        string
}

// VerifyEmailOutput nunca expone user_id/email/secreto.
type VerifyEmailOutput struct {
	Status string // "active" | "already_verified"
	Method string // "link" | "otp"
}

// VerifyEmailService orquesta la verificación. Solo interfaces de dominio.
type VerifyEmailService struct {
	Store   auth.VerificationStore
	Users   user.UserRepository
	Idem    shared.IdempotencyStore
	Audit   shared.AuditLogger
	Metrics VerifyMetricsPort
	Tracer  TracerPort
	Sleep   func(time.Duration)
}

func NewVerifyEmailService(
	store auth.VerificationStore,
	users user.UserRepository,
	idem shared.IdempotencyStore,
	audit shared.AuditLogger,
	metrics VerifyMetricsPort,
	tracer TracerPort,
) *VerifyEmailService {
	if metrics == nil {
		metrics = NoopVerifyMetrics{}
	}
	if tracer == nil {
		tracer = NoopTracer{}
	}
	if audit == nil {
		audit = NoopAudit{}
	}
	return &VerifyEmailService{
		Store: store, Users: users, Idem: idem, Audit: audit,
		Metrics: metrics, Tracer: tracer, Sleep: time.Sleep,
	}
}

func (s *VerifyEmailService) jitter() time.Duration {
	const min, max = int64(40), int64(80)
	n, err := rand.Int(rand.Reader, big.NewInt(max-min+1))
	if err != nil {
		return 40 * time.Millisecond
	}
	return time.Duration(min+n.Int64()) * time.Millisecond
}

// Execute implementa el flujo §3 del spec CU-REG-02.
func (s *VerifyEmailService) Execute(ctx context.Context, in VerifyEmailInput) (*VerifyEmailOutput, error) {
	start := time.Now()
	ctx, span := s.Tracer.Start(ctx, "UseCase.VerifyEmail")
	defer span.End()

	if _, err := uuid.Parse(in.RequestID); err != nil {
		s.Metrics.IncVerification("validation_failed", "none")
		return nil, &ValidationError{Fields: []FieldError{{Field: "request_id", Reason: "INVALID_FORMAT"}}}
	}
	hasToken := in.Token != ""
	hasCode := in.Code != ""
	if hasToken == hasCode {
		s.Metrics.IncVerification("validation_failed", "none")
		return nil, &ValidationError{Fields: []FieldError{{Field: "token", Reason: "EXACTLY_ONE_REQUIRED"}}}
	}
	var hash, method string
	if hasToken {
		h, err := auth.ParseTokenInput(in.Token)
		if err != nil {
			s.Metrics.IncVerification("validation_failed", "link")
			return nil, &ValidationError{Fields: []FieldError{{Field: "token", Reason: "INVALID_FORMAT"}}}
		}
		hash, method = h, "link"
	} else {
		h, err := auth.ParseOTPInput(in.Code)
		if err != nil {
			s.Metrics.IncVerification("validation_failed", "otp")
			return nil, &ValidationError{Fields: []FieldError{{Field: "code", Reason: "INVALID_FORMAT"}}}
		}
		hash, method = h, "otp"
	}

	// Idempotencia 24h.
	if s.Idem != nil {
		if v, found, _ := s.Idem.Get(ctx, in.RequestID); found {
			s.Metrics.IncVerification(v, method)
			s.Metrics.ObserveVerificationDuration(time.Since(start).Seconds())
			return &VerifyEmailOutput{Status: v, Method: method}, nil
		}
	}

	rec, ferr := s.Store.FindAlive(ctx, hash)
	if ferr != nil {
		// ¿Es el token activador (doble-clic/prefetch)? → already_verified.
		if out, ok := s.alreadyVerified(ctx, hash, method, in.RequestID, start); ok {
			return out, nil
		}
		return s.invalid(ctx, in, method, start, "invalid_or_expired")
	}

	// Defensa en profundidad: comparación en tiempo constante aunque el
	// lookup ya filtró (SEC-01). Solo el hash correspondiente al método.
	var stored string
	if method == "link" {
		stored = rec.TokenHash
	} else {
		stored = rec.OTPHash
	}
	if stored == "" || subtle.ConstantTimeCompare([]byte(stored), []byte(hash)) != 1 {
		left, burned, _ := s.Store.IncrementAttempts(ctx, hash)
		if burned {
			s.Metrics.IncAttemptsBurned()
		}
		_ = left
		return s.invalid(ctx, in, method, start, "invalid_or_expired")
	}

	consumed, cerr := s.Store.ConsumeAtomically(ctx, rec.UserID, hash, method)
	if cerr != nil {
		if errors.Is(cerr, auth.ErrInvalidOrExpired) || errors.Is(cerr, user.ErrNotFound) {
			// Carrera: otro request consumió primero. Si fue este secreto el
			// activador (doble-clic), responde already_verified; si no, genérico.
			if out, ok := s.alreadyVerified(ctx, hash, method, in.RequestID, start); ok {
				return out, nil
			}
			return s.invalid(ctx, in, method, start, "invalid_or_expired")
		}
		s.Metrics.IncVerification("error", method)
		return nil, fmt.Errorf("consume verification: %w", auth.ErrInfra)
	}

	s.putIdem(ctx, in.RequestID, "active")
	_ = s.Audit.Log(ctx, "user.verify", map[string]string{
		"result": "success", "user_id": consumed.UserID,
		"email_hash": consumed.EmailHash, "method": method,
	})
	s.Metrics.IncVerification("success", method)
	s.Metrics.ObserveVerificationDuration(time.Since(start).Seconds())
	return &VerifyEmailOutput{Status: "active", Method: consumed.Method}, nil
}

// alreadyVerified resuelve idempotencia del activador (doble-clic/prefetch).
func (s *VerifyEmailService) alreadyVerified(ctx context.Context, hash, method, requestID string, start time.Time) (*VerifyEmailOutput, bool) {
	uid, ok, _ := s.Store.WasActivatedBy(ctx, hash)
	if !ok || uid == "" {
		return nil, false
	}
	s.putIdem(ctx, requestID, "already_verified")
	_ = s.Audit.Log(ctx, "user.verify", map[string]string{
		"result": "already_verified", "user_id": uid, "method": method,
	})
	s.Metrics.IncVerification("already_verified", method)
	s.Metrics.ObserveVerificationDuration(time.Since(start).Seconds())
	return &VerifyEmailOutput{Status: "already_verified", Method: method}, true
}

// invalid aplica delay uniforme 40-80ms + métrica + auditoría genérica (anti-oráculo).
func (s *VerifyEmailService) invalid(ctx context.Context, in VerifyEmailInput, method string, start time.Time, result string) (*VerifyEmailOutput, error) {
	s.Sleep(s.jitter())
	_ = s.Audit.Log(ctx, "user.verify_failed", map[string]string{
		"result": result, "method": method,
	})
	s.Metrics.IncVerification(result, method)
	s.Metrics.ObserveVerificationDuration(time.Since(start).Seconds())
	return nil, auth.ErrInvalidOrExpired
}

func (s *VerifyEmailService) putIdem(ctx context.Context, requestID, status string) {
	if s.Idem == nil {
		return
	}
	_ = s.Idem.Put(ctx, requestID, status, 24*time.Hour)
}
