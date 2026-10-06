package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/shared"
	"auth-identity-service/internal/domain/user"

	"github.com/google/uuid"
)

// ChangePasswordInput entrada change (Bearer ya validado por middleware).
// SID identifica la sesión actual a preservar ("" si Bearer legacy).
type ChangePasswordInput struct {
	User        AuthUser
	SID         string
	Current     string
	HasCurrent  bool
	NewPassword string
	StepUpToken string // solo federated-set (header X-Step-Up-Token)
	RequestID   string
}

// ChangePasswordOutput rotación aplicada (sesión actual intacta).
type ChangePasswordOutput struct {
	Status          string // siempre "password_changed"
	SessionsRevoked int
	Via             string // "change" | "set"
}

// StepUpChecker verifica fast-pass o token scopeado (lo implementa
// *StepUpService; interfaz para tests sin Redis/DB).
type StepUpChecker interface {
	Check(ctx context.Context, callerUserID string, bearerAuthTime time.Time, scope auth.StepUpScope, token string) (string, error)
}

// ChangePasswordService orquesta POST /password/change (CU-CRED-02).
// Con hash: current_password equivale a Step-Up. Federated-set: exige
// guard Step-Up (fast-pass o token scope cred:change-password).
type ChangePasswordService struct {
	History   auth.PasswordHistoryStore
	Hasher    auth.PasswordHasher
	Breach    auth.BreachChecker
	Tracker   auth.AttemptTracker
	StepUp    StepUpChecker
	Outbox    OutboxEnqueuer
	Idem      shared.IdempotencyStore
	Audit     shared.AuditLogger
	Metrics   ChangeMetricsPort
	Tracer    TracerPort
	Sleep     func(time.Duration)
	localDeny map[string]struct{}
}

func NewChangePasswordService(
	history auth.PasswordHistoryStore,
	hasher auth.PasswordHasher,
	breach auth.BreachChecker,
	tracker auth.AttemptTracker,
	stepUp StepUpChecker,
	outbox OutboxEnqueuer,
	idem shared.IdempotencyStore,
	audit shared.AuditLogger,
	metrics ChangeMetricsPort,
	tracer TracerPort,
) *ChangePasswordService {
	if metrics == nil {
		metrics = NoopChangeMetrics{}
	}
	if tracer == nil {
		tracer = NoopTracer{}
	}
	if audit == nil {
		audit = NoopAudit{}
	}
	return &ChangePasswordService{
		History: history, Hasher: hasher, Breach: breach, Tracker: tracker,
		StepUp: stepUp, Outbox: outbox, Idem: idem, Audit: audit,
		Metrics: metrics, Tracer: tracer, Sleep: time.Sleep,
		localDeny: defaultDenyList(),
	}
}

const pwdChanged = "password_changed"

// Execute implementa §3: auth→policy→StepUp-actual→history→hash→Tx→200.
// Nunca toca tokens_valid_after (el actual sobrevive sin re-login).
func (s *ChangePasswordService) Execute(ctx context.Context, in ChangePasswordInput) (*ChangePasswordOutput, error) {
	start := time.Now()
	ctx, span := s.Tracer.Start(ctx, "UseCase.ChangePassword")
	defer span.End()

	if _, err := uuid.Parse(in.RequestID); err != nil {
		s.Metrics.IncChange("validation_failed", "change")
		return nil, &ValidationError{Fields: []FieldError{{Field: "request_id", Reason: "INVALID_FORMAT"}}}
	}
	if in.NewPassword == "" {
		s.Metrics.IncChange("validation_failed", "change")
		return nil, &ValidationError{Fields: []FieldError{{Field: "new_password", Reason: "REQUIRED"}}}
	}
	// Idempotencia 24h: replay del RequestID que ya rotó → mismo 200.
	if s.Idem != nil {
		if v, found, _ := s.Idem.Get(ctx, in.RequestID); found && v == pwdChanged {
			s.Metrics.IncChange("replayed", "change")
			s.Metrics.ObserveChangeDuration(time.Since(start).Seconds())
			return &ChangePasswordOutput{Status: pwdChanged, Via: "change"}, nil
		}
	}

	acct, err := s.History.Current(ctx, in.User.ID)
	if err != nil {
		s.Metrics.IncChange("error", "change")
		return nil, fmt.Errorf("current account: %w", auth.ErrInfra)
	}
	if acct.Status != user.StatusActive {
		s.Metrics.IncChange("error", "change")
		return nil, auth.ErrAccountUnavailable
	}
	// Lock cuenta (reuso CU-AUTH-01): durante el lock incluso la buena da 401.
	if s.Tracker != nil {
		if locked, _ := s.Tracker.IsLocked(ctx, acct.ID); locked {
			_ = s.Audit.Log(ctx, "password.change", map[string]string{
				"action": "password.change", "user_id": acct.ID, "result": "locked",
			})
			s.Metrics.IncChange("invalid_current", "change")
			s.Metrics.ObserveChangeDuration(time.Since(start).Seconds())
			return nil, auth.ErrInvalidCurrent
		}
	}
	via := "change"

	// Policy CU-REG-01 (con parte local real) + HIBP. Sin fails de cuenta.
	if pwErr := auth.ValidateSyntax(in.NewPassword, auth.LocalPart(acct.Email)); pwErr != nil {
		s.Metrics.IncChange("policy_failed", via)
		s.Metrics.ObserveChangeDuration(time.Since(start).Seconds())
		return nil, &ValidationError{Fields: []FieldError{{Field: "new_password", Reason: mapPasswordReason(pwErr)}}}
	}
	if perr := s.checkBreach(ctx, in.NewPassword, via, start); perr != nil {
		return nil, perr
	}

	if acct.HasPassword() {
		if !in.HasCurrent || in.Current == "" {
			s.Metrics.IncChange("validation_failed", via)
			s.Metrics.ObserveChangeDuration(time.Since(start).Seconds())
			return nil, &ValidationError{Fields: []FieldError{{Field: "current_password", Reason: "MISSING_CURRENT"}}}
		}
		ok, verr := s.Hasher.Verify(ctx, in.Current, acct.Hash)
		if verr != nil || !ok {
			s.recordFail(ctx, acct)
			_ = s.Audit.Log(ctx, "password.change", map[string]string{
				"action": "password.change", "user_id": acct.ID, "result": "invalid_current",
			})
			s.Metrics.IncChange("invalid_current", via)
			s.Metrics.ObserveChangeDuration(time.Since(start).Seconds())
			return nil, auth.ErrInvalidCurrent
		}
	} else {
		via = "set"
		if in.HasCurrent {
			s.Metrics.IncChange("validation_failed", via)
			s.Metrics.ObserveChangeDuration(time.Since(start).Seconds())
			return nil, &ValidationError{Fields: []FieldError{{Field: "current_password", Reason: "UNEXPECTED_CURRENT"}}}
		}
		if s.StepUp == nil {
			s.Metrics.IncChange("error", via)
			return nil, fmt.Errorf("step-up unavailable: %w", auth.ErrInfra)
		}
		if _, serr := s.StepUp.Check(ctx, acct.ID, in.User.AuthTime, auth.ScopeChangePassword, in.StepUpToken); serr != nil {
			_ = s.Audit.Log(ctx, "password.change", map[string]string{
				"action": "password.change", "user_id": acct.ID, "result": "step_up_failed",
			})
			s.Metrics.IncChange("step_up_required", via)
			s.Metrics.ObserveChangeDuration(time.Since(start).Seconds())
			return nil, serr
		}
	}

	// ≠actual y ∉historial-5 (Verify×N; corrupto se ignora + WARN).
	hist, herr := s.History.LastN(ctx, acct.ID, auth.PasswordHistoryN)
	if herr != nil {
		s.Metrics.IncChange("error", via)
		return nil, fmt.Errorf("history: %w", auth.ErrInfra)
	}
	reused, inHist, dirty := auth.DistinctFromHashes(in.NewPassword,
		func(plain, hash string) (bool, error) { return s.Hasher.Verify(ctx, plain, hash) },
		acct.Hash, hist)
	if dirty > 0 {
		_ = s.Audit.Log(ctx, "password.change", map[string]string{
			"action": "password.change", "user_id": acct.ID, "result": "history_dirty",
		})
	}
	if reused {
		s.Metrics.IncChange("reused", via)
		s.Metrics.ObserveChangeDuration(time.Since(start).Seconds())
		return nil, auth.ErrPasswordReused
	}
	if inHist {
		s.Metrics.IncHistoryHit()
		s.Metrics.IncChange("in_history", via)
		s.Metrics.ObserveChangeDuration(time.Since(start).Seconds())
		return nil, auth.ErrPasswordInHistory
	}

	newHash, herr := s.Hasher.Hash(ctx, in.NewPassword)
	if herr != nil {
		s.Metrics.IncChange("error", via)
		return nil, fmt.Errorf("hash password: %w", auth.ErrInfra)
	}
	newVer, peers, rerr := s.History.RotateTx(ctx, acct.ID, acct.Hash, newHash, acct.Ver, in.SID, in.RequestID)
	if rerr != nil {
		if errors.Is(rerr, auth.ErrPasswordReused) {
			s.Metrics.IncChange("reused", via)
			s.Metrics.ObserveChangeDuration(time.Since(start).Seconds())
			return nil, auth.ErrPasswordReused
		}
		s.Metrics.IncChange("error", via)
		return nil, fmt.Errorf("rotate: %w", auth.ErrInfra)
	}
	s.Metrics.IncPeersRevoked(peers)
	_ = s.Audit.Log(ctx, "password.change", map[string]string{
		"action": "password.change", "user_id": acct.ID, "result": "success",
		"via": via, "peers_revoked": itoaChange(peers), "password_ver": itoaChange(newVer),
	})
	s.Metrics.IncChange("success", via)
	s.Metrics.ObserveChangeDuration(time.Since(start).Seconds())
	if s.Idem != nil {
		_ = s.Idem.Put(ctx, in.RequestID, pwdChanged, 24*time.Hour)
	}
	return &ChangePasswordOutput{Status: pwdChanged, SessionsRevoked: peers, Via: via}, nil
}

// checkBreach aplica HIBP con fallback a lista local (igual registro/confirm).
func (s *ChangePasswordService) checkBreach(ctx context.Context, password, via string, start time.Time) error {
	if s.Breach == nil {
		return nil
	}
	compromised, berr := s.Breach.IsCompromised(ctx, password)
	if berr != nil {
		s.Metrics.IncHibpFallback()
		if _, denied := s.localDeny[password]; denied {
			s.Metrics.IncChange("policy_failed", via)
			s.Metrics.ObserveChangeDuration(time.Since(start).Seconds())
			return &ValidationError{Fields: []FieldError{{Field: "new_password", Reason: "COMPROMISED"}}}
		}
		return nil
	}
	if compromised {
		s.Metrics.IncChange("policy_failed", via)
		s.Metrics.ObserveChangeDuration(time.Since(start).Seconds())
		return &ValidationError{Fields: []FieldError{{Field: "new_password", Reason: "COMPROMISED"}}}
	}
	return nil
}

// recordFail suma fail al lock exponencial compartido con login (+email 1/h).
func (s *ChangePasswordService) recordFail(ctx context.Context, acct *auth.ChangeAccount) {
	if s.Tracker == nil {
		return
	}
	lockedNow, sendEmail, _ := s.Tracker.RecordFail(ctx, acct.ID)
	_ = lockedNow
	if lockedNow {
		s.Metrics.IncChangeLock()
	}
	if sendEmail && s.Outbox != nil {
		body, _ := json.Marshal(map[string]any{
			"user_id": acct.ID, "email": acct.Email, "action": "notify_lock",
		})
		_ = s.Outbox.Enqueue(ctx, []user.OutboxPayload{{
			EventID: newUUIDv7(), EventType: "security.login_lock",
			AggregateID: acct.ID, Topic: "auth.security.login_lock.v1",
			PayloadJSON: body,
		}})
	}
}

func itoaChange(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
