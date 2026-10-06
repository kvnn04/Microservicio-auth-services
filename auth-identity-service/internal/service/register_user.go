package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/shared"
	"auth-identity-service/internal/domain/user"

	"github.com/google/uuid"
)

// Puertos de observabilidad (T-05): el servicio no importa Prometheus/OTel.
type MetricsPort interface {
	IncRegistration(status string)
	ObserveRegistrationDuration(seconds float64)
	IncHibpFallback()
	// CU-REG-03 (transversal, métricas INTERNAS nunca expuestas al cliente):
	IncUniquenessProbe(outcome string)
	IncNotifyOwner(throttled bool)
	IncIPBlocked()
}

type Span interface{ End() }

type TracerPort interface {
	Start(ctx context.Context, name string) (context.Context, Span)
}

// OutboxEnqueuer persiste eventos sin crear usuario (rama shadow).
type OutboxEnqueuer interface {
	Enqueue(ctx context.Context, events []user.OutboxPayload) error
}

type NoopMetrics struct{}

func (NoopMetrics) IncRegistration(string)              {}
func (NoopMetrics) ObserveRegistrationDuration(float64) {}
func (NoopMetrics) IncHibpFallback()                    {}
func (NoopMetrics) IncUniquenessProbe(string)            {}
func (NoopMetrics) IncNotifyOwner(bool)                  {}
func (NoopMetrics) IncIPBlocked()                         {}

type noopSpan struct{}

func (noopSpan) End() {}

type NoopTracer struct{}

func (NoopTracer) Start(ctx context.Context, _ string) (context.Context, Span) {
	return ctx, noopSpan{}
}

type NoopAudit struct{}

func (NoopAudit) Log(_ context.Context, _ string, _ map[string]string) error { return nil }

// FieldError fallo de validación por campo (contrato 400).
type FieldError struct {
	Field  string
	Reason string
}

// ValidationError error tipado de dominio para 400.
type ValidationError struct {
	Fields []FieldError
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%v: %v", auth.ErrValidation, e.Fields)
}

func (e *ValidationError) Unwrap() error { return auth.ErrValidation }

// RegisterUserInput DTO de entrada (ya parseado del HTTP).
type RegisterUserInput struct {
	EmailRaw       string
	Password       string
	TermsAccepted  bool
	TermsVersion   string
	PrivacyVersion string
	RequestID      string
	IP             string
	UserAgent      string
}

// RegisterUserOutput nunca expone user_id/email/tokens (anti-enumeración).
type RegisterUserOutput struct {
	Status             string
	IsShadowDuplicate  bool
	IsIdempotentReplay bool
	HibpFallback       bool
}

// RegisterUserService orquesta CU-REG-01. Solo interfaces de dominio.
// CU-REG-03 (transversal): Throttle limita el notify al dueño (nil = permitir,
// preserva comportamiento CU-REG-01 en tests legacy).
type RegisterUserService struct {
	Users     user.UserRepository
	Hasher    auth.PasswordHasher
	Breach    auth.BreachChecker
	Tokens    auth.VerificationTokenIssuer
	Outbox    OutboxEnqueuer
	Idem      shared.IdempotencyStore
	Audit     shared.AuditLogger
	Metrics   MetricsPort
	Tracer    TracerPort
	Throttle  user.NotifyThrottle
	// CU-REG-05 (transversal): Legal exige DB (fail-closed); nil = skip (tests).
	Legal shared.LegalVersionProvider
	// Consents telemetría legal; nil = Noop.
	Consents  ConsentMetricsPort
	Sleep     func(time.Duration)
	JitterMin time.Duration
	JitterMax time.Duration
	localDeny map[string]struct{}
}

func NewRegisterUserService(
	users user.UserRepository,
	hasher auth.PasswordHasher,
	breach auth.BreachChecker,
	tokens auth.VerificationTokenIssuer,
	outbox OutboxEnqueuer,
	idem shared.IdempotencyStore,
	audit shared.AuditLogger,
	metrics MetricsPort,
	tracer TracerPort,
) *RegisterUserService {
	if metrics == nil {
		metrics = NoopMetrics{}
	}
	if tracer == nil {
		tracer = NoopTracer{}
	}
	if audit == nil {
		audit = NoopAudit{}
	}
	return &RegisterUserService{
		Users: users, Hasher: hasher, Breach: breach, Tokens: tokens,
		Outbox: outbox, Idem: idem, Audit: audit,
		Metrics: metrics, Tracer: tracer,
		Sleep: time.Sleep,
		JitterMin: 80 * time.Millisecond, JitterMax: 120 * time.Millisecond,
		localDeny: defaultDenyList(),
	}
}

func defaultDenyList() map[string]struct{} {
	common := []string{"123456789012", "password123!", "qwerty123456!", "letmein!2026xy", "admin123456!", "welcome1234!"}
	m := make(map[string]struct{}, len(common))
	for _, p := range common {
		m[p] = struct{}{}
	}
	return m
}

const dummyPassword = "Dummy!P4ssword-For-Timing-Mitigation-2026"

func (s *RegisterUserService) jitter() time.Duration {
	if s.JitterMax <= s.JitterMin {
		return s.JitterMin
	}
	delta := int64(s.JitterMax - s.JitterMin)
	n, err := rand.Int(rand.Reader, big.NewInt(delta+1))
	if err != nil {
		return s.JitterMin
	}
	return s.JitterMin + time.Duration(n.Int64())
}

// Execute implementa el flujo §3 del spec.
func (s *RegisterUserService) Execute(ctx context.Context, in RegisterUserInput) (*RegisterUserOutput, error) {
	start := time.Now()
	ctx, span := s.Tracer.Start(ctx, "UseCase.RegisterUser")
	defer span.End()

	if _, err := uuid.Parse(in.RequestID); err != nil {
		s.Metrics.IncRegistration("validation_failed")
		return nil, &ValidationError{Fields: []FieldError{{Field: "request_id", Reason: "INVALID_FORMAT"}}}
	}
	var fields []FieldError
	// CU-REG-05: con Legal, terms_* los valida el bloque consentimiento
	// (códigos TERMS_REQUIRED/OUTDATED); sin Legal, chequeo legado.
	if s.Legal == nil {
		if !in.TermsAccepted {
			fields = append(fields, FieldError{Field: "terms_accepted", Reason: "TERMS_NOT_ACCEPTED"})
		}
		if in.TermsVersion == "" || in.PrivacyVersion == "" {
			fields = append(fields, FieldError{Field: "terms_version", Reason: "INVALID_FORMAT"})
		}
	}
	normalized, _, err := user.Normalize(in.EmailRaw)
	if err != nil {
		if errors.Is(err, user.ErrEmailTooLong) {
			fields = append(fields, FieldError{Field: "email", Reason: "TOO_LONG"})
		} else {
			fields = append(fields, FieldError{Field: "email", Reason: "INVALID_FORMAT"})
		}
	}
	if pwErr := auth.ValidateSyntax(in.Password, auth.LocalPart(normalized)); pwErr != nil {
		fields = append(fields, FieldError{Field: "password", Reason: mapPasswordReason(pwErr)})
	}
	if len(fields) > 0 {
		s.Metrics.IncRegistration("validation_failed")
		return nil, &ValidationError{Fields: fields}
	}

	// CU-REG-05: consentimiento legal ANTES de Probe/hash/outbox (fail-fast,
	// sin fuga timing de existencia). Legal==nil solo en tests legacy.
	if s.Legal != nil {
		if ferr := CheckConsentFast(in.TermsAccepted, in.TermsVersion, in.PrivacyVersion); ferr != nil {
			s.Metrics.IncRegistration("validation_failed")
			consentMetrics(s.Consents).IncConsentRejected("missing")
			return nil, ConsentValidationError(ferr)
		}
		activeT, activeP, gerr := s.Legal.GetActive(ctx)
		if gerr != nil {
			s.Metrics.IncRegistration("error")
			return nil, fmt.Errorf("legal versions: %w", auth.ErrInfra)
		}
		if cerr := CheckConsentAgainstActive(in.TermsVersion, in.PrivacyVersion, activeT, activeP); cerr != nil {
			s.Metrics.IncRegistration("validation_failed")
			cm := consentMetrics(s.Consents)
			cm.IncConsentRejected("outdated")
			doc := "terms"
			if in.TermsVersion == activeT.Version {
				doc = "privacy"
			}
			cm.IncConsentOutdated(doc)
			return nil, cerr
		}
	}

	hibpFallback := false
	if s.Breach != nil {
		compromised, berr := s.Breach.IsCompromised(ctx, in.Password)
		if berr != nil {
			hibpFallback = true
			s.Metrics.IncHibpFallback()
			if _, denied := s.localDeny[in.Password]; denied {
				s.Metrics.IncRegistration("validation_failed")
				return nil, &ValidationError{Fields: []FieldError{{Field: "password", Reason: "COMPROMISED"}}}
			}
		} else if compromised {
			s.Metrics.IncRegistration("validation_failed")
			return nil, &ValidationError{Fields: []FieldError{{Field: "password", Reason: "COMPROMISED"}}}
		}
	}

	if s.Idem != nil {
		if _, found, _ := s.Idem.Get(ctx, in.RequestID); found {
			s.Metrics.IncRegistration("success")
			s.Metrics.ObserveRegistrationDuration(time.Since(start).Seconds())
			return &RegisterUserOutput{Status: "pending_verification", IsIdempotentReplay: true, HibpFallback: hibpFallback}, nil
		}
	}

	existing, findErr := s.Users.FindByEmailNormalized(ctx, normalized)
	if findErr != nil && !errors.Is(findErr, user.ErrNotFound) {
		s.Metrics.IncRegistration("error")
		return nil, fmt.Errorf("find user: %w", auth.ErrInfra)
	}
	found := findErr == nil && existing != nil

	var pwdHash string
	var hashErr error
	if found {
		_, hashErr = s.Hasher.Hash(ctx, dummyPassword)
	} else {
		pwdHash, hashErr = s.Hasher.Hash(ctx, in.Password)
	}
	s.Sleep(s.jitter())
	if hashErr != nil {
		s.Metrics.IncRegistration("error")
		return nil, fmt.Errorf("hash password: %w", auth.ErrInfra)
	}

	now := time.Now().UTC()
	emailHash := sha256Hex(normalized)
	ipHash := sha256Hex(in.IP + "/24")
	uaHash := sha256Hex(in.UserAgent)

	if found {
		// CU-REG-03: throttling del notify (1/h + 3/día). El exceso solo
		// genera audit throttled; la respuesta sigue idéntica (nunca 429).
		notifyAllowed := true
		if s.Throttle != nil {
			if ok, terr := s.Throttle.AllowOwnerNotify(ctx, emailHash); terr == nil {
				notifyAllowed = ok
			}
		}
		outcome := user.DecideProbe(true, notifyAllowed)
		s.Metrics.IncUniquenessProbe(string(outcome))
		s.Metrics.IncNotifyOwner(!notifyAllowed)
		notified := "true"
		if !notifyAllowed {
			notified = "false-throttled"
		}
		if user.ShouldNotify(true, notifyAllowed) {
			secPayload, _ := json.Marshal(map[string]any{
				"email_hash": "sha256:" + emailHash,
				"email_domain": user.DomainOf(normalized),
				"user_id": existing.ID,
				"user_status": string(existing.Status),
				"is_existing": true, "ip_hash": "sha256:" + ipHash, "action": "notify_owner",
			})
			if s.Outbox != nil {
				_ = s.Outbox.Enqueue(ctx, []user.OutboxPayload{{
					EventID: newUUIDv7(), EventType: "security.registration_attempted",
					AggregateID: existing.ID, Topic: "auth.security.registration_attempted.v1",
					PayloadJSON: secPayload,
				}})
			}
		}
		_ = s.Audit.Log(ctx, "uniqueness.probe", map[string]string{
			"action": "uniqueness.probe", "email_hash": emailHash,
			"user_id": existing.ID, "found": "true", "result": string(outcome),
			"notified": notified, "ip_hash": ipHash,
		})
		_ = s.Audit.Log(ctx, "user.register", map[string]string{
			"result": "duplicate_shadow", "email_hash": emailHash,
			"ip_hash": ipHash, "user_agent_hash": uaHash, "terms_version": in.TermsVersion,
		})
		s.Metrics.IncRegistration("duplicate_shadow")
		s.Metrics.ObserveRegistrationDuration(time.Since(start).Seconds())
		s.putIdem(ctx, in.RequestID)
		return &RegisterUserOutput{Status: "pending_verification", IsShadowDuplicate: true, HibpFallback: hibpFallback}, nil
	}
	s.Metrics.IncUniquenessProbe(string(user.ProbeUnique))

	userID := newUUIDv7()
	plainToken, tokenHash, terr := s.Tokens.Generate()
	if terr != nil {
		s.Metrics.IncRegistration("error")
		return nil, fmt.Errorf("generate token: %w", auth.ErrInfra)
	}
	_ = plainToken
	u, uerr := user.NewUser(userID, trimOriginal(in.EmailRaw), normalized, pwdHash, in.TermsVersion, in.PrivacyVersion, now)
	if uerr != nil {
		s.Metrics.IncRegistration("validation_failed")
		return nil, &ValidationError{Fields: []FieldError{{Field: "email", Reason: "INVALID_FORMAT"}}}
	}
	regPayload, _ := json.Marshal(map[string]any{
		"user_id": userID, "email_hash": "sha256:" + emailHash,
		"email_domain": user.DomainOf(normalized), "status": "pending_verification",
		"terms_version": in.TermsVersion, "request_id": in.RequestID,
	})
	verPayload, _ := json.Marshal(map[string]any{
		"user_id": userID, "email": normalized,
		"verification_token_hash": "sha256:" + tokenHash,
		"expires_at": now.Add(auth.VerificationTTL).UTC().Format("2006-01-02T15:04:05Z"),
		"attempts_allowed": auth.VerificationMaxAttempts,
	})
	auditPayload, _ := json.Marshal(map[string]any{
		"action": "user.register", "user_id": userID, "email_hash": "sha256:" + emailHash,
		"result": "success", "ip_hash": "sha256:" + ipHash,
		"user_agent_hash": "sha256:" + uaHash, "terms_version": in.TermsVersion,
	})
	events := []user.OutboxPayload{
		{EventID: newUUIDv7(), EventType: "user.registered", AggregateID: userID, Topic: "auth.user.registered.v1", PayloadJSON: regPayload},
		{EventID: newUUIDv7(), EventType: "email.verification_requested", AggregateID: userID, Topic: "auth.email.verification_requested.v1", PayloadJSON: verPayload},
		{EventID: newUUIDv7(), EventType: "audit.user_register", AggregateID: userID, Topic: "auth.audit.v1", PayloadJSON: auditPayload},
	}
	var cerr error
	if s.Legal != nil {
		// CU-REG-05: misma Tx + ledger (source=classic) + evento legal.
		cerr = s.Users.CreateWithConsents(ctx, u, events, tokenHash, user.RegistrationContext{
			IPHash: ipHash, UAHash: uaHash, Source: "classic", RequestID: in.RequestID,
		})
	} else {
		cerr = s.Users.CreateWithOutbox(ctx, u, events, tokenHash, in.RequestID)
	}
	if cerr != nil {
		if errors.Is(cerr, user.ErrDuplicateShadow) || errors.Is(cerr, user.ErrAlreadyExists) {
			_ = s.Audit.Log(ctx, "user.register", map[string]string{"result": "duplicate_shadow", "email_hash": emailHash})
			s.Metrics.IncRegistration("duplicate_shadow")
			s.Metrics.ObserveRegistrationDuration(time.Since(start).Seconds())
			return &RegisterUserOutput{Status: "pending_verification", IsShadowDuplicate: true, HibpFallback: hibpFallback}, nil
		}
		s.Metrics.IncRegistration("error")
		return nil, fmt.Errorf("create user: %w", auth.ErrInfra)
	}
	_ = s.Audit.Log(ctx, "user.register", map[string]string{
		"result": "success", "email_hash": emailHash,
		"ip_hash": ipHash, "user_agent_hash": uaHash, "terms_version": in.TermsVersion,
	})
	s.Metrics.IncRegistration("success")
	s.Metrics.ObserveRegistrationDuration(time.Since(start).Seconds())
	if s.Legal != nil {
		cm := consentMetrics(s.Consents)
		cm.IncConsentRecorded("terms", "classic")
		cm.IncConsentRecorded("privacy", "classic")
	}
	s.putIdem(ctx, in.RequestID)
	return &RegisterUserOutput{Status: "pending_verification", HibpFallback: hibpFallback}, nil
}

func (s *RegisterUserService) putIdem(ctx context.Context, requestID string) {
	if s.Idem == nil {
		return
	}
	_ = s.Idem.Put(ctx, requestID, "pending_verification", 24*time.Hour)
}

func mapPasswordReason(err error) string {
	switch {
	case errors.Is(err, auth.ErrPasswordTooShort):
		return "TOO_SHORT"
	case errors.Is(err, auth.ErrPasswordTooLong):
		return "TOO_LONG"
	case errors.Is(err, auth.ErrPasswordMissingCls):
		return "MISSING_CLASS"
	case errors.Is(err, auth.ErrPasswordCompromisd):
		return "COMPROMISED"
	case errors.Is(err, auth.ErrPasswordEqualsMail):
		return "EQUALS_EMAIL"
	case errors.Is(err, auth.ErrPasswordRepeating):
		return "REPEATING"
	default:
		return "INVALID_FORMAT"
	}
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func trimOriginal(raw string) string {
	start, end := 0, len(raw)
	for start < end && (raw[start] == ' ' || raw[start] == '\t' || raw[start] == '\n' || raw[start] == '\r') {
		start++
	}
	for end > start && (raw[end-1] == ' ' || raw[end-1] == '\t' || raw[end-1] == '\n' || raw[end-1] == '\r') {
		end--
	}
	return raw[start:end]
}

func newUUIDv7() string {
	if id, err := uuid.NewV7(); err == nil {
		return id.String()
	}
	return uuid.NewString()
}
