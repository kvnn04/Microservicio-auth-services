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
	"unicode/utf8"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/shared"
	"auth-identity-service/internal/domain/user"

	"github.com/google/uuid"
)

// LoginMetricsPort telemetría CU-AUTH-01 (T-05). Sin SDK directo.
type LoginMetricsPort interface {
	IncLogin(result string)
	ObserveLoginDuration(seconds float64)
	IncLoginFailure(reasonInternal string)
	IncLoginLock()
	IncLoginLockEmail(throttled bool)
}

// NoopLoginMetrics default sin telemetría.
type NoopLoginMetrics struct{}

func (NoopLoginMetrics) IncLogin(string)                {}
func (NoopLoginMetrics) ObserveLoginDuration(float64)   {}
func (NoopLoginMetrics) IncLoginFailure(string)        {}
func (NoopLoginMetrics) IncLoginLock()                 {}
func (NoopLoginMetrics) IncLoginLockEmail(bool)        {}

// LoginInput entrada login (validación laxa de password aquí).
type LoginInput struct {
	EmailRaw  string
	Password  string
	RequestID string
	IP        string
	UserAgent string
}

// LoginOutput: Status active (con Session) o mfa_required (con Challenge).
type LoginOutput struct {
	Status    string // "active" | "mfa_required"
	Session   *SessionData
	Challenge *MFAChallengeData
}

// MFAChallengeData pre-token aislado (aud=mfa-challenge, solo /mfa/verify).
type MFAChallengeData struct {
	Token      string
	Methods    []string
	ExpiresIn  int
}

// LoginService orquesta CU-AUTH-01. Solo puertos de dominio.
type LoginService struct {
	Users    user.UserRepository
	Hasher   auth.PasswordHasher
	Tracker  auth.AttemptTracker
	Sessions auth.SessionIssuer
	MFA      auth.MFAPreTokenIssuer
	// Challenges registra el pre-token para single-use (nil = sin registro).
	Challenges auth.MFAChallengeStore
	Outbox   OutboxEnqueuer
	Idem     shared.IdempotencyStore
	Audit    shared.AuditLogger
	Metrics  LoginMetricsPort
	Tracer   TracerPort
	Sleep    func(time.Duration)
}

func NewLoginService(
	users user.UserRepository,
	hasher auth.PasswordHasher,
	tracker auth.AttemptTracker,
	sessions auth.SessionIssuer,
	mfa auth.MFAPreTokenIssuer,
	challenges auth.MFAChallengeStore,
	outbox OutboxEnqueuer,
	idem shared.IdempotencyStore,
	audit shared.AuditLogger,
	metrics LoginMetricsPort,
	tracer TracerPort,
) *LoginService {
	if metrics == nil {
		metrics = NoopLoginMetrics{}
	}
	if tracer == nil {
		tracer = NoopTracer{}
	}
	if audit == nil {
		audit = NoopAudit{}
	}
	return &LoginService{
		Users: users, Hasher: hasher, Tracker: tracker, Sessions: sessions,
		MFA: mfa, Challenges: challenges, Outbox: outbox, Idem: idem, Audit: audit,
		Metrics: metrics, Tracer: tracer, Sleep: time.Sleep,
	}
}

func loginJitter() time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(41))
	if err != nil {
		return auth.LoginJitterMin
	}
	return auth.LoginJitterMin + time.Duration(n.Int64())*time.Millisecond
}

// Execute implementa el flujo §3: camino homogéneo siempre, 401 único.
func (s *LoginService) Execute(ctx context.Context, in LoginInput) (*LoginOutput, error) {
	start := time.Now()
	ctx, span := s.Tracer.Start(ctx, "UseCase.Login")
	defer span.End()

	// 1. Forma laxa (rápida, sin contadores de cuenta).
	normalized, _, nerr := user.Normalize(in.EmailRaw)
	if nerr != nil {
		s.Metrics.IncLogin("error")
		return nil, &ValidationError{Fields: []FieldError{{Field: "email", Reason: "INVALID_FORMAT"}}}
	}
	if in.Password == "" || utf8.RuneCountInString(in.Password) > 128 || len(in.Password) > 512 {
		s.Metrics.IncLogin("error")
		return nil, &ValidationError{Fields: []FieldError{{Field: "password", Reason: "INVALID_FORMAT"}}}
	}
	if _, err := uuid.Parse(in.RequestID); err != nil {
		return nil, &ValidationError{Fields: []FieldError{{Field: "request_id", Reason: "INVALID_FORMAT"}}}
	}

	emailHash := loginSHA256(normalized)
	ipHash := loginSHA256(in.IP + "/24")
	uaHash := loginSHA256(in.UserAgent)
	deviceHash := loginSHA256(ipHash + uaHash)

	// 2. Rate-limit (fast-reject, sin DB/hash).
	if s.Tracker != nil {
		if lerr := s.Tracker.CheckLimits(ctx, in.IP, emailHash); lerr != nil {
			s.Metrics.IncLogin("rate_limited")
			return nil, lerr
		}
	}

	// Idempotencia: replay misma respuesta sin duplicar fails/outbox.
	if s.Idem != nil {
		if v, found, _ := s.Idem.Get(ctx, in.RequestID); found {
			s.Metrics.ObserveLoginDuration(time.Since(start).Seconds())
			return loginReplayOutput(v)
		}
	}

	// 3. Lookup (guarda found, no ramifica respuesta).
	var foundUser *user.User
	found := false
	if u, ferr := s.Users.FindByEmailNormalized(ctx, normalized); ferr == nil && u != nil {
		foundUser = u
		found = true
	} else if ferr != nil && !errors.Is(ferr, user.ErrNotFound) {
		s.Metrics.IncLogin("error")
		return nil, fmt.Errorf("find user: %w", auth.ErrInfra)
	}
	lockKey := "acct:" + emailHash
	if found {
		lockKey = foundUser.ID
	}
	locked := false
	if s.Tracker != nil {
		if l, _ := s.Tracker.IsLocked(ctx, lockKey); l {
			locked = true
		}
	}

	// 4. Camino homogéneo SIEMPRE: Verify real o dummy + jitter.
	var verifyOK bool
	if found && foundUser.PasswordHash != "" {
		ok, verr := s.Hasher.Verify(ctx, in.Password, foundUser.PasswordHash)
		if verr == nil {
			verifyOK = ok
		}
	} else {
		_, _ = s.Hasher.Hash(ctx, auth.DummyLoginPassword)
	}
	s.Sleep(loginJitter())

	// 5. Decide en memoria (sin filtrar).
	mfa := found && foundUser.MFAEnabled
	outcome := auth.DecideLogin(found, verifyOK, locked, statusOf(foundUser), mfa)
	if outcome == auth.LoginInvalid {
		reason := loginReason(found, verifyOK, locked, foundUser)
		if s.Tracker != nil {
			lockedNow, sendEmail, _ := s.Tracker.RecordFail(ctx, lockKey)
			_ = lockedNow
			if sendEmail && found {
				s.enqueueLockEmail(ctx, foundUser)
				s.Metrics.IncLoginLockEmail(false)
			} else if sendEmail {
				s.Metrics.IncLoginLockEmail(true)
			}
			if lockedNow {
				s.Metrics.IncLoginLock()
			}
		}
		s.enqueueLoginEvent(ctx, "login.failed", lockKeyID(foundUser), emailHash, map[string]any{
			"reason_internal": reason,
		}, in.RequestID)
		_ = s.Audit.Log(ctx, "login.attempt", map[string]string{
			"action": "login.attempt", "email_hash": emailHash,
			"result": "invalid", "reason_internal": reason,
			"ip_hash": ipHash, "device_hash": deviceHash,
		})
		s.Metrics.IncLogin("invalid")
		s.Metrics.IncLoginFailure(reason)
		s.Metrics.ObserveLoginDuration(time.Since(start).Seconds())
		s.putLoginIdem(ctx, in.RequestID, "invalid")
		return nil, auth.ErrInvalidCredentials
	}

	// 6. Éxito: resetea fails + bifurca sesión/pre-token.
	if s.Tracker != nil {
		_ = s.Tracker.ResetOnSuccess(ctx, lockKey)
	}
	if outcome == auth.LoginMFARequired {
		token, challengeID, expiresIn, merr := s.MFA.IssueChallenge(ctx, foundUser.ID)
		if merr != nil {
			s.Metrics.IncLogin("error")
			return nil, fmt.Errorf("mfa challenge: %w", auth.ErrInfra)
		}
		// Single-use: registra el challenge (sin esto verify siempre 401).
		if s.Challenges != nil {
			if rerr := s.Challenges.Register(ctx, challengeID, foundUser.ID); rerr != nil {
				s.Metrics.IncLogin("error")
				return nil, fmt.Errorf("challenge store: %w", auth.ErrInfra)
			}
		}
		s.enqueueLoginEvent(ctx, "login.mfa_challenged", foundUser.ID, emailHash, map[string]any{
			"challenge_id": challengeID, "methods": []string{"totp"},
		}, in.RequestID)
		_ = s.Audit.Log(ctx, "login.attempt", map[string]string{
			"action": "login.attempt", "email_hash": emailHash, "user_id": foundUser.ID,
			"result": "mfa_required", "ip_hash": ipHash, "device_hash": deviceHash,
		})
		s.Metrics.IncLogin("mfa_required")
		s.Metrics.ObserveLoginDuration(time.Since(start).Seconds())
		s.putLoginIdem(ctx, in.RequestID, "mfa_required")
		return &LoginOutput{Status: "mfa_required", Challenge: &MFAChallengeData{
			Token: token, Methods: []string{"totp"}, ExpiresIn: expiresIn,
		}}, nil
	}
	atPair, serr := s.Sessions.Issue(ctx, auth.SessionRequest{
		UserID: foundUser.ID, Method: auth.MethodPassword,
		AMR: []auth.AMR{auth.AMRPassword}, AuthTime: time.Now().UTC(),
		Device: auth.Device{IPHash: ipHash, UAHash: uaHash,
			Label: auth.DeviceLabel(in.UserAgent), IPMasked: auth.MaskIP(in.IP)},
		Roles: []string{"user"},
	})
	if serr != nil {
		s.Metrics.IncLogin("error")
		return nil, fmt.Errorf("issue session: %w", auth.ErrInfra)
	}
	s.enqueueLoginEvent(ctx, "login.success", foundUser.ID, emailHash, map[string]any{
		"mfa": false, "device_hash": "sha256:" + deviceHash,
	}, in.RequestID)
	_ = s.Audit.Log(ctx, "login.attempt", map[string]string{
		"action": "login.attempt", "email_hash": emailHash, "user_id": foundUser.ID,
		"result": "success", "ip_hash": ipHash, "device_hash": deviceHash,
	})
	s.Metrics.IncLogin("success")
	s.Metrics.ObserveLoginDuration(time.Since(start).Seconds())
	s.putLoginIdem(ctx, in.RequestID, "active")
	return &LoginOutput{Status: "active", Session: &SessionData{
		AccessToken: atPair.AccessJWT, RefreshTokenID: atPair.RefreshPlain,
		ExpiresAt: atPair.ExpiresAt.Unix(), SID: atPair.SID,
	}}, nil
}

func statusOf(u *user.User) user.Status {
	if u == nil {
		return ""
	}
	return u.Status
}

// loginReason interno (jamás al cliente): no_user|bad_password|not_active|locked|no_password.
func loginReason(found, verifyOK, locked bool, u *user.User) string {
	if !found {
		return "no_user"
	}
	if locked {
		return "locked"
	}
	if u != nil && u.Status != user.StatusActive {
		return "not_active"
	}
	if u != nil && u.PasswordHash == "" {
		return "no_password"
	}
	if !verifyOK {
		return "bad_password"
	}
	return "unknown"
}

func lockKeyID(u *user.User) string {
	if u == nil {
		return ""
	}
	return u.ID
}

func (s *LoginService) enqueueLoginEvent(ctx context.Context, typ, key, emailHash string, extra map[string]any, requestID string) {
	if s.Outbox == nil {
		return
	}
	payload := map[string]any{"email_hash": "sha256:" + emailHash, "request_id": requestID}
	for k, v := range extra {
		payload[k] = v
	}
	if key != "" {
		payload["user_id"] = key
	}
	body, _ := json.Marshal(payload)
	agg := key
	if agg == "" {
		agg = emailHash
	}
	_ = s.Outbox.Enqueue(ctx, []user.OutboxPayload{{
		EventID: newUUIDv7(), EventType: typ, AggregateID: agg,
		Topic: "auth.login.v1", PayloadJSON: body,
	}})
}

func (s *LoginService) enqueueLockEmail(ctx context.Context, u *user.User) {
	// Aviso de bloqueo al dueño (throttle 1/h ya decidido en el tracker).
	// Solo si hay dueño conocido (found); si no existe, no hay a quién avisar.
	if s.Outbox == nil || u == nil {
		return
	}
	body, _ := json.Marshal(map[string]any{
		"user_id": u.ID, "email": u.EmailNormalized,
		"action": "notify_lock",
	})
	_ = s.Outbox.Enqueue(ctx, []user.OutboxPayload{{
		EventID: newUUIDv7(), EventType: "security.login_lock",
		AggregateID: u.ID, Topic: "auth.security.login_lock.v1",
		PayloadJSON: body,
	}})
}

func (s *LoginService) putLoginIdem(ctx context.Context, requestID, status string) {
	if s.Idem == nil || requestID == "" {
		return
	}
	_ = s.Idem.Put(ctx, requestID, status, 24*time.Hour)
}

// loginReplayOutput reconstruye respuesta idempotente (sin side-effects).
func loginReplayOutput(status string) (*LoginOutput, error) {
	switch status {
	case "active":
		return &LoginOutput{Status: "active"}, nil
	case "mfa_required":
		return &LoginOutput{Status: "mfa_required"}, nil
	default:
		return nil, auth.ErrInvalidCredentials
	}
}

func loginSHA256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
