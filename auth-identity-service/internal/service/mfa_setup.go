package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/shared"
	"auth-identity-service/internal/domain/user"
)

// MFAMetricsPort telemetría CU-AUTH-02 (T-05). Sin SDK directo.
type MFAMetricsPort interface {
	IncMFA(op, result string)
	ObserveVerifyDuration(seconds float64)
	IncChallengeBurned(reason string)
	IncReplayBlocked()
}

// NoopMFAMetrics default sin telemetría.
type NoopMFAMetrics struct{}

func (NoopMFAMetrics) IncMFA(string, string)         {}
func (NoopMFAMetrics) ObserveVerifyDuration(float64) {}
func (NoopMFAMetrics) IncChallengeBurned(string)     {}
func (NoopMFAMetrics) IncReplayBlocked()             {}

func mfaJitter() time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(31))
	if err != nil {
		return 20 * time.Millisecond
	}
	return 20*time.Millisecond + time.Duration(n.Int64())*time.Millisecond
}

// MFAService orquesta setup/enable/verify/disable. Solo puertos de dominio.
type MFAService struct {
	TOTP     auth.TOTPProvider
	Box      auth.SecretBox
	Secrets  auth.MFASecretStore
	Chal     auth.MFAChallengeStore
	PreToken auth.MFAPreTokenValidator
	// CU-AUTH-03: issuer/store de backups (nil-safe: sin backups si nil).
	BackupIssuer auth.BackupCodeIssuer
	BackupStore  auth.BackupCodeStore
	// CU-AUTH-03: métricas backup (nil-safe).
	BackupMetrics BackupMetricsPort
	Users         user.UserRepository
	Links         user.FederatedLinkStore
	Sessions      auth.SessionIssuer
	Outbox        OutboxEnqueuer
	Idem          shared.IdempotencyStore
	Audit         shared.AuditLogger
	Metrics       MFAMetricsPort
	Tracer        TracerPort
	Issuer        string
	Sleep         func(time.Duration)
}

func NewMFAService(
	totp auth.TOTPProvider,
	box auth.SecretBox,
	secrets auth.MFASecretStore,
	chal auth.MFAChallengeStore,
	preToken auth.MFAPreTokenValidator,
	backupIssuer auth.BackupCodeIssuer,
	backupStore auth.BackupCodeStore,
	users user.UserRepository,
	links user.FederatedLinkStore,
	sessions auth.SessionIssuer,
	outbox OutboxEnqueuer,
	idem shared.IdempotencyStore,
	audit shared.AuditLogger,
	metrics MFAMetricsPort,
	tracer TracerPort,
	issuer string,
) *MFAService {
	if metrics == nil {
		metrics = NoopMFAMetrics{}
	}
	if tracer == nil {
		tracer = NoopTracer{}
	}
	if audit == nil {
		audit = NoopAudit{}
	}
	return &MFAService{
		TOTP: totp, Box: box, Secrets: secrets, Chal: chal, PreToken: preToken,
		BackupIssuer: backupIssuer, BackupStore: backupStore,
		Users: users, Links: links, Sessions: sessions,
		Outbox: outbox, Idem: idem, Audit: audit,
		Metrics: metrics, Tracer: tracer, Issuer: issuer, Sleep: time.Sleep,
	}
}

func (s *MFAService) fresh(au AuthUser) error {
	return user.RequireFreshAuth(au.AuthTime, time.Now().UTC(), user.StepUpMaxAge)
}

// freshStepUp acepta Step-Up token scopeado (CU-AUTH-06) además de frescura.
// El middleware RequireStepUp ya verificó el guard; el ctx lo atestigua.
func (s *MFAService) freshStepUp(ctx context.Context, au AuthUser, scope auth.StepUpScope) error {
	if StepUpSatisfied(ctx, scope) {
		return nil
	}
	return s.fresh(au)
}

func (s *MFAService) activeUser(ctx context.Context, userID string) (*user.User, error) {
	u, err := s.Users.FindByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("find user: %w", auth.ErrInfra)
	}
	if u.Status != user.StatusActive {
		return nil, auth.ErrAccountUnavailable
	}
	return u, nil
}

// SetupInput entrada enrollment (sesión fresca).
type SetupInput struct {
	User      AuthUser
	RequestID string
}

// SetupOutput secreto exhibido UNA vez + otpauth (el front renderiza QR).
type SetupOutput struct {
	SecretB32  string
	OTPAuthURL string
	ExpiresIn  int
}

// Setup genera secreto, lo cifra y lo deja staged (supersede anterior).
func (s *MFAService) Setup(ctx context.Context, in SetupInput) (*SetupOutput, error) {
	ctx, span := s.Tracer.Start(ctx, "UseCase.MFASetup")
	defer span.End()
	if err := s.freshStepUp(ctx, in.User, auth.ScopeMFARotate); err != nil {
		s.Metrics.IncMFA("setup", "step_up_required")
		return nil, err
	}
	u, err := s.activeUser(ctx, in.User.ID)
	if err != nil {
		return nil, err
	}
	if _, serr := s.Secrets.GetActive(ctx, u.ID); serr == nil {
		s.Metrics.IncMFA("setup", "already")
		return nil, auth.ErrAlreadyEnabled
	}
	raw, b32, gerr := s.TOTP.GenerateSecret(ctx)
	if gerr != nil {
		s.Metrics.IncMFA("setup", "error")
		return nil, fmt.Errorf("secret: %w", auth.ErrInfra)
	}
	sealed, eerr := s.Box.Encrypt(ctx, u.ID, raw)
	if eerr != nil {
		s.Metrics.IncMFA("setup", "error")
		return nil, fmt.Errorf("encrypt: %w", auth.ErrInfra)
	}
	if serr := s.Secrets.Stage(ctx, u.ID, sealed); serr != nil {
		s.Metrics.IncMFA("setup", "error")
		return nil, fmt.Errorf("stage: %w", auth.ErrInfra)
	}
	_ = s.Audit.Log(ctx, "mfa.setup", map[string]string{
		"action": "mfa.setup", "user_id": u.ID, "result": "staged",
	})
	s.Metrics.IncMFA("setup", "ok")
	return &SetupOutput{
		SecretB32:  b32,
		OTPAuthURL: fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30", s.Issuer, u.EmailNormalized, b32, s.Issuer),
		ExpiresIn:  600,
	}, nil
}

// EnableInput confirmación con código de la app.
type EnableInput struct {
	User      AuthUser
	Code      string
	RequestID string
}

// EnableOutput códigos de rescate (UNA vez, delega CU-AUTH-03).
type EnableOutput struct {
	Status      string
	BackupCodes []string
}

// Enable valida el código staged y promueve a activo + backups.
func (s *MFAService) Enable(ctx context.Context, in EnableInput) (*EnableOutput, error) {
	ctx, span := s.Tracer.Start(ctx, "UseCase.MFAEnable")
	defer span.End()
	if err := s.freshStepUp(ctx, in.User, auth.ScopeMFARotate); err != nil {
		s.Metrics.IncMFA("enable", "step_up_required")
		return nil, err
	}
	u, err := s.activeUser(ctx, in.User.ID)
	if err != nil {
		return nil, err
	}
	if !validOTPFormat(in.Code) {
		s.Metrics.IncMFA("enable", "invalid")
		return nil, &ValidationError{Fields: []FieldError{{Field: "code", Reason: "INVALID_FORMAT"}}}
	}
	enc, expired, gerr := s.Secrets.Staged(ctx, u.ID)
	if gerr != nil {
		s.Metrics.IncMFA("enable", "invalid")
		return nil, auth.ErrNoStaged
	}
	if expired {
		s.Metrics.IncMFA("enable", "invalid")
		return nil, auth.ErrStagedExpired
	}
	raw, derr := s.Box.Decrypt(ctx, u.ID, enc)
	if derr != nil {
		s.Metrics.IncMFA("enable", "error")
		return nil, fmt.Errorf("decrypt: %w", auth.ErrInfra)
	}
	if _, ok := s.TOTP.Validate(ctx, raw, in.Code, auth.NewCounter(time.Now().UTC())); !ok {
		s.Metrics.IncMFA("enable", "invalid")
		s.Sleep(mfaJitter())
		return nil, auth.ErrInvalidMFA
	}
	var codes []string
	if s.BackupIssuer != nil && s.BackupStore != nil {
		var berr error
		codes, _, berr = s.generateBackupSet(ctx, u.ID, false)
		if berr != nil {
			s.Metrics.IncMFA("enable", "error")
			return nil, fmt.Errorf("backups: %w", auth.ErrInfra)
		}
	}
	if perr := s.Secrets.PromoteTx(ctx, u.ID); perr != nil {
		s.Metrics.IncMFA("enable", "error")
		return nil, fmt.Errorf("promote: %w", auth.ErrInfra)
	}
	s.enqueueMFA(ctx, u.ID, "mfa.enabled", map[string]any{"method": "totp"})
	_ = s.Audit.Log(ctx, "mfa.enable", map[string]string{
		"action": "mfa.enable", "user_id": u.ID, "result": "enabled",
	})
	s.Metrics.IncMFA("enable", "ok")
	return &EnableOutput{Status: "enabled", BackupCodes: codes}, nil
}

func validOTPFormat(code string) bool {
	if len(code) != 6 {
		return false
	}
	for i := 0; i < 6; i++ {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}

func (s *MFAService) enqueueMFA(ctx context.Context, userID, typ string, extra map[string]any) {
	if s.Outbox == nil {
		return
	}
	payload := map[string]any{"user_id": userID}
	for k, v := range extra {
		payload[k] = v
	}
	body, _ := json.Marshal(payload)
	_ = s.Outbox.Enqueue(ctx, []user.OutboxPayload{{
		EventID: newUUIDv7(), EventType: typ, AggregateID: userID,
		Topic: "auth.mfa.v1", PayloadJSON: body,
	}})
}

func mfaSHA256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
