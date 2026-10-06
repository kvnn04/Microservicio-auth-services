package service

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/shared"
	"auth-identity-service/internal/domain/user"

	"github.com/google/uuid"
)

// Modos de satisfacción del guard (inyectados al ctx para las ops).
const (
	StepUpFastPass = "fast_pass"
	StepUpToken    = "token"
)

type stepUpCtxKey string

const (
	stepUpModeKey  stepUpCtxKey = "step_up_mode"
	stepUpScopeKey stepUpCtxKey = "step_up_scope"
)

// StepUpContext marca el request como satisfecho por el guard
// (lo llama el middleware tras verificar fast-pass o token).
func StepUpContext(ctx context.Context, mode string, scope auth.StepUpScope) context.Context {
	ctx = context.WithValue(ctx, stepUpModeKey, mode)
	return context.WithValue(ctx, stepUpScopeKey, string(scope))
}

// StepUpSatisfied indica si el guard ya autorizó este scope en el request.
// Las ops recableadas lo consultan antes de exigir frescura propia.
func StepUpSatisfied(ctx context.Context, scope auth.StepUpScope) bool {
	mode, _ := ctx.Value(stepUpModeKey).(string)
	if mode != StepUpFastPass && mode != StepUpToken {
		return false
	}
	got, _ := ctx.Value(stepUpScopeKey).(string)
	return got == string(scope)
}

// StepUpChallengeInput entrada challenge (Bearer ya validado por middleware).
type StepUpChallengeInput struct {
	User      AuthUser
	Scope     string
	Password  string
	Code      string
	RequestID string
}

// StepUpChallengeOutput token scopeado de un uso.
type StepUpChallengeOutput struct {
	Token     string
	Scope     string
	ExpiresIn int
}

// StepUpService orquesta Challenge + Guard (CU-AUTH-06). Solo puertos.
// Reusa AttemptTracker (locks CU-AUTH-01), TOTP/Backup (CU-AUTH-02/03) y
// firma Ed25519 con aud aislado (CU-AUTH-04, distinto aud).
type StepUpService struct {
	Users         user.UserRepository
	Hasher        auth.PasswordHasher
	Tracker       auth.AttemptTracker
	TOTP          auth.TOTPProvider
	Box           auth.SecretBox
	Secrets       auth.MFASecretStore
	Chal          auth.MFAChallengeStore
	BackupIssuer  auth.BackupCodeIssuer
	BackupStore   auth.BackupCodeStore
	BackupMetrics BackupMetricsPort
	Tokens        auth.StepUpTokenIssuer
	JTIs          auth.StepUpJTIStore
	Outbox        OutboxEnqueuer
	Idem          shared.IdempotencyStore
	Audit         shared.AuditLogger
	Metrics       StepUpMetricsPort
	Tracer        TracerPort
	Sleep         func(time.Duration)
}

func NewStepUpService(
	users user.UserRepository,
	hasher auth.PasswordHasher,
	tracker auth.AttemptTracker,
	totp auth.TOTPProvider,
	box auth.SecretBox,
	secrets auth.MFASecretStore,
	chal auth.MFAChallengeStore,
	backupIssuer auth.BackupCodeIssuer,
	backupStore auth.BackupCodeStore,
	tokens auth.StepUpTokenIssuer,
	jtis auth.StepUpJTIStore,
	outbox OutboxEnqueuer,
	idem shared.IdempotencyStore,
	audit shared.AuditLogger,
	metrics StepUpMetricsPort,
	tracer TracerPort,
) *StepUpService {
	if metrics == nil {
		metrics = NoopStepUpMetrics{}
	}
	if tracer == nil {
		tracer = NoopTracer{}
	}
	if audit == nil {
		audit = NoopAudit{}
	}
	return &StepUpService{
		Users: users, Hasher: hasher, Tracker: tracker,
		TOTP: totp, Box: box, Secrets: secrets, Chal: chal,
		BackupIssuer: backupIssuer, BackupStore: backupStore,
		Tokens: tokens, JTIs: jtis, Outbox: outbox, Idem: idem,
		Audit: audit, Metrics: metrics, Tracer: tracer, Sleep: time.Sleep,
	}
}

func stepUpJitter() time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(41))
	if err != nil {
		return 40 * time.Millisecond
	}
	return 40*time.Millisecond + time.Duration(n.Int64())*time.Millisecond
}

// Challenge valida scope → factores exigidos (doble si ambos) → emite token.
// Federated-only sin nada local → Relogin (el fast-pass sigue disponible).
func (s *StepUpService) Challenge(ctx context.Context, in StepUpChallengeInput) (*StepUpChallengeOutput, error) {
	start := time.Now()
	ctx, span := s.Tracer.Start(ctx, "UseCase.StepUpChallenge")
	defer span.End()

	scope := auth.StepUpScope(in.Scope)
	if !scope.Valid() {
		s.Metrics.IncStepUp("challenge", "unknown_scope")
		return nil, auth.ErrUnknownScope
	}
	hasIdem := false
	if _, err := uuid.Parse(in.RequestID); err == nil && in.RequestID != "" {
		hasIdem = true
		if s.Idem != nil {
			if v, found, _ := s.Idem.Get(ctx, in.RequestID); found {
				if tok, ok := stepUpReplayToken(v, string(scope)); ok {
					s.Metrics.IncStepUp("challenge", "replayed")
					s.Metrics.ObserveStepUpDuration("challenge", time.Since(start).Seconds())
					return &StepUpChallengeOutput{Token: tok, Scope: string(scope), ExpiresIn: 300}, nil
				}
			}
		}
	}

	u, err := s.Users.FindByID(ctx, in.User.ID)
	if err != nil {
		s.Metrics.IncStepUp("challenge", "error")
		return nil, fmt.Errorf("find user: %w", auth.ErrInfra)
	}
	if u.Status != user.StatusActive {
		s.Metrics.IncStepUp("challenge", "error")
		return nil, auth.ErrAccountUnavailable
	}
	hasPassword := u.PasswordHash != ""
	hasMFA := u.MFAEnabled
	if !hasPassword && !hasMFA {
		_ = s.Audit.Log(ctx, "stepup.challenge", map[string]string{
			"action": "stepup.challenge", "user_id": u.ID,
			"scope": string(scope), "result": "relogin_required",
		})
		s.Metrics.IncStepUp("challenge", "relogin_required")
		s.Metrics.ObserveStepUpDuration("challenge", time.Since(start).Seconds())
		return nil, auth.ErrStepUpRelogin
	}

	// Lock cuenta (reuso CU-AUTH-01): 5 fails/15min → 401 opaco hasta expirar.
	if s.Tracker != nil {
		if locked, _ := s.Tracker.IsLocked(ctx, u.ID); locked {
			return s.invalidChallenge(ctx, u.ID, string(scope), start, "locked")
		}
	}

	amr := []string{}
	if hasPassword {
		if in.Password == "" {
			s.Metrics.IncStepUp("challenge", "validation_failed")
			return nil, &ValidationError{Fields: []FieldError{{Field: "password", Reason: "REQUIRED"}}}
		}
		ok, verr := s.Hasher.Verify(ctx, in.Password, u.PasswordHash)
		if verr != nil || !ok {
			s.recordFail(ctx, u)
			return s.invalidChallenge(ctx, u.ID, string(scope), start, "bad_password")
		}
		amr = append(amr, "pwd")
	}
	if hasMFA {
		method, ok := s.checkSecondFactor(ctx, u.ID, in.Code)
		if !ok {
			if method == "form" {
				s.Metrics.IncStepUp("challenge", "validation_failed")
				return nil, &ValidationError{Fields: []FieldError{{Field: "code", Reason: "INVALID_FORMAT"}}}
			}
			s.recordFail(ctx, u)
			return s.invalidChallenge(ctx, u.ID, string(scope), start, "bad_second")
		}
		amr = append(amr, method)
	}

	token, jti, terr := s.Tokens.IssueToken(ctx, u.ID, scope, amr)
	if terr != nil {
		s.Metrics.IncStepUp("challenge", "error")
		return nil, fmt.Errorf("issue step-up: %w", auth.ErrInfra)
	}
	// Single-use: sin Redis no hay token (fail-closed; fast-pass offline intacto).
	if s.JTIs == nil {
		s.Metrics.IncStepUp("challenge", "error")
		return nil, auth.ErrStepUpUnavailable
	}
	if jerr := s.JTIs.Save(ctx, jti, u.ID, string(scope)); jerr != nil {
		s.Metrics.IncStepUp("challenge", "error")
		return nil, auth.ErrStepUpUnavailable
	}
	if s.Tracker != nil {
		_ = s.Tracker.ResetOnSuccess(ctx, u.ID)
	}
	if hasIdem {
		s.putStepUpIdem(ctx, in.RequestID, string(scope), token)
	}
	s.enqueueStepUp(ctx, u.ID, "stepup.passed", map[string]any{
		"scope": string(scope), "jti": jti,
	})
	_ = s.Audit.Log(ctx, "stepup.challenge", map[string]string{
		"action": "stepup.challenge", "user_id": u.ID,
		"scope": string(scope), "result": "issued", "jti": jti,
	})
	s.Metrics.IncStepUp("challenge", "issued")
	s.Metrics.ObserveStepUpDuration("challenge", time.Since(start).Seconds())
	return &StepUpChallengeOutput{Token: token, Scope: string(scope), ExpiresIn: 300}, nil
}

// checkSecondFactor valida TOTP (6d ±1 + anti-replay compartido con MFA) o
// backup (10ch, SÍ lo consume: single-use global + alerta). Retorna
// (método|"form"|"fail", ok).
func (s *StepUpService) checkSecondFactor(ctx context.Context, userID, code string) (string, bool) {
	trimmed := code
	if canonical, cerr := auth.Canonicalize(trimmed); cerr == nil {
		return s.checkBackupFactor(ctx, userID, canonical)
	}
	if !validOTPFormat(trimmed) {
		return "form", false
	}
	enc, gerr := s.Secrets.GetActive(ctx, userID)
	if gerr != nil {
		return "fail", false
	}
	raw, derr := s.Box.Decrypt(ctx, userID, enc)
	if derr != nil {
		return "fail", false
	}
	counter := auth.NewCounter(time.Now().UTC())
	matched, ok := s.TOTP.Validate(ctx, raw, trimmed, counter)
	if !ok {
		return "fail", false
	}
	if s.Chal.Uncheckable(ctx) {
		return "fail", false
	}
	fresh, rerr := s.Chal.MarkReplay(ctx, userID, matched)
	if rerr != nil || !fresh {
		return "fail", false
	}
	return "totp", true
}

// checkBackupFactor consume el código (irreversible, con rotación de pepper).
func (s *StepUpService) checkBackupFactor(ctx context.Context, userID, canonical string) (string, bool) {
	if s.BackupIssuer == nil || s.BackupStore == nil {
		return "fail", false
	}
	hash := s.BackupIssuer.Hash(canonical)
	note := newUUIDv7()
	if _, cerr := s.BackupStore.ConsumeTx(ctx, userID, hash, note); cerr != nil {
		if prev, ok := s.BackupIssuer.HashPrev(canonical); ok {
			if _, perr := s.BackupStore.ConsumeTx(ctx, userID, prev, note); perr == nil {
				bm := backupMetrics(s.BackupMetrics)
				bm.IncBackup("consume", "ok")
				return "backup", true
			}
		}
		return "fail", false
	}
	bm := backupMetrics(s.BackupMetrics)
	bm.IncBackup("consume", "ok")
	return "backup", true
}

// invalidChallenge: jitter 40-80ms + 401 opaco (password y TOTP idénticos).
func (s *StepUpService) invalidChallenge(ctx context.Context, userID, scope string, start time.Time, _ string) (*StepUpChallengeOutput, error) {
	s.Sleep(stepUpJitter())
	_ = s.Audit.Log(ctx, "stepup.challenge", map[string]string{
		"action": "stepup.challenge", "user_id": userID,
		"scope": scope, "result": "invalid",
	})
	s.enqueueStepUp(ctx, userID, "stepup.failed", map[string]any{"scope": scope})
	s.Metrics.IncStepUp("challenge", "invalid")
	s.Metrics.ObserveStepUpDuration("challenge", time.Since(start).Seconds())
	return nil, auth.ErrStepUpInvalid
}

// recordFail suma fallo al lock exponencial compartido (+email throttled 1/h).
func (s *StepUpService) recordFail(ctx context.Context, u *user.User) {
	if s.Tracker == nil {
		return
	}
	lockedNow, sendEmail, _ := s.Tracker.RecordFail(ctx, u.ID)
	_ = lockedNow
	if sendEmail && s.Outbox != nil {
		body, _ := json.Marshal(map[string]any{
			"user_id": u.ID, "email": u.EmailNormalized, "action": "notify_lock",
		})
		_ = s.Outbox.Enqueue(ctx, []user.OutboxPayload{{
			EventID: newUUIDv7(), EventType: "security.login_lock",
			AggregateID: u.ID, Topic: "auth.security.login_lock.v1",
			PayloadJSON: body,
		}})
	}
}

// Check implementa el guard: fast-pass offline (sin Redis) o token 1-uso-1-scope.
// Retorna modo ("fast_pass"|"token") o error de dominio mapeable a 401/500.
func (s *StepUpService) Check(ctx context.Context, callerUserID string, bearerAuthTime time.Time, scope auth.StepUpScope, token string) (string, error) {
	start := time.Now()
	ctx, span := s.Tracer.Start(ctx, "Guard.StepUpCheck")
	defer span.End()

	if auth.DecideStepUp(bearerAuthTime, time.Now().UTC(), true) == auth.StepUpFastPass {
		_ = s.Audit.Log(ctx, "stepup.check", map[string]string{
			"action": "stepup.check", "user_id": callerUserID,
			"scope": string(scope), "result": "fast_pass",
		})
		s.Metrics.IncStepUp("guard", "fast_pass")
		s.Metrics.ObserveStepUpDuration("guard", time.Since(start).Seconds())
		return StepUpFastPass, nil
	}
	if token == "" {
		s.Metrics.IncStepUp("guard", "required")
		s.Metrics.ObserveStepUpDuration("guard", time.Since(start).Seconds())
		return "", auth.ErrStepUpRequired
	}
	claims, verr := s.Tokens.VerifyToken(token)
	if verr != nil {
		return s.invalidGuard(ctx, callerUserID, string(scope), start, "invalid")
	}
	if claims.Sub == "" || claims.Sub != callerUserID || claims.Scope != string(scope) {
		return s.invalidGuard(ctx, callerUserID, string(scope), start, "mismatch")
	}
	if s.JTIs == nil {
		s.Metrics.IncStepUp("guard", "error")
		return "", auth.ErrStepUpUnavailable
	}
	sub, savedScope, found, cerr := s.JTIs.Consume(ctx, claims.JTI)
	if cerr != nil {
		s.Metrics.IncStepUp("guard", "error")
		return "", auth.ErrStepUpUnavailable
	}
	if !found || sub != callerUserID || savedScope != string(scope) {
		s.Metrics.IncReuseBlocked()
		_ = s.Audit.Log(ctx, "stepup.check", map[string]string{
			"action": "stepup.check", "user_id": callerUserID,
			"scope": string(scope), "result": "reused", "jti": claims.JTI,
		})
		s.enqueueStepUp(ctx, callerUserID, "stepup.reused", map[string]any{
			"scope": string(scope), "jti": claims.JTI,
		})
		s.Metrics.IncStepUp("guard", "reused")
		s.Metrics.ObserveStepUpDuration("guard", time.Since(start).Seconds())
		return "", auth.ErrStepUpReused
	}
	_ = s.Audit.Log(ctx, "stepup.check", map[string]string{
		"action": "stepup.check", "user_id": callerUserID,
		"scope": string(scope), "result": "used", "jti": claims.JTI,
	})
	s.Metrics.IncStepUp("guard", "used")
	s.Metrics.ObserveStepUpDuration("guard", time.Since(start).Seconds())
	return StepUpToken, nil
}

func (s *StepUpService) invalidGuard(ctx context.Context, userID, scope string, start time.Time, _ string) (string, error) {
	_ = s.Audit.Log(ctx, "stepup.check", map[string]string{
		"action": "stepup.check", "user_id": userID,
		"scope": scope, "result": "invalid",
	})
	s.Metrics.IncStepUp("guard", "invalid")
	s.Metrics.ObserveStepUpDuration("guard", time.Since(start).Seconds())
	return "", auth.ErrStepUpInvalid
}

func (s *StepUpService) enqueueStepUp(ctx context.Context, userID, typ string, extra map[string]any) {
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
		Topic: "auth.stepup.v1", PayloadJSON: body,
	}})
}

func (s *StepUpService) putStepUpIdem(ctx context.Context, requestID, scope, token string) {
	if s.Idem == nil || requestID == "" {
		return
	}
	_ = s.Idem.Put(ctx, requestID, scope+"\n"+token, 60*time.Second)
}

// stepUpReplayToken recupera el token idempotente si el scope coincide.
func stepUpReplayToken(v, scope string) (string, bool) {
	for i := 0; i < len(v); i++ {
		if v[i] == '\n' {
			if v[:i] == scope && i+1 < len(v) {
				return v[i+1:], true
			}
			return "", false
		}
	}
	return "", false
}
