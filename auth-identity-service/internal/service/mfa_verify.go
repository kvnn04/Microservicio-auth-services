package service

import (
	"context"
	"fmt"
	"time"

	"auth-identity-service/internal/domain/auth"

	"github.com/google/uuid"
)

// VerifyInput entrada verify (SIN Bearer; el pre-token es la auth).
type VerifyInput struct {
	MFAToken  string
	Code      string
	RequestID string
	IP        string
	UserAgent string
}

// VerifyOutput sesión final (cookies en handler).
type VerifyOutput struct {
	Status  string // "active"
	Session *SessionData
	// CU-AUTH-03: método y estado de backups (cero en TOTP).
	Method    string // "totp" | "backup"
	Remaining int    // backups restantes tras consumir (-1 si no aplica)
	Warning   bool   // remaining<=2
	Exhausted bool   // remaining==0 tras consumir el último
}

// BackupMetricsPort vive en backup_codes.go (mismo package).

// Verify resuelve el desafío MFA (TOTP o backup autodetectado).
// Todo fallo es 401 opaco (salvo 500 replay indetectable y 400 de forma).
// Delay 20-50ms en 401. Mismo challenge/fails/401 para ambos tipos (Q5).
func (s *MFAService) Verify(ctx context.Context, in VerifyInput) (*VerifyOutput, error) {
	start := time.Now()
	ctx, span := s.Tracer.Start(ctx, "UseCase.MFAVerify")
	defer span.End()

	if in.MFAToken == "" {
		s.Metrics.IncMFA("verify", "invalid")
		return nil, &ValidationError{Fields: []FieldError{{Field: "mfa_token", Reason: "REQUIRED"}}}
	}
	// Autodetección (Q4): 10ch backup vs 6d TOTP; otro → 400 sin challenge.
	backupCanonical, backupErr := auth.Canonicalize(in.Code)
	isBackup := backupErr == nil
	if !isBackup && !validOTPFormat(in.Code) {
		s.Metrics.IncMFA("verify", "invalid")
		return nil, &ValidationError{Fields: []FieldError{{Field: "code", Reason: "INVALID_FORMAT"}}}
	}
	if _, err := uuid.Parse(in.RequestID); err != nil {
		return nil, &ValidationError{Fields: []FieldError{{Field: "request_id", Reason: "INVALID_FORMAT"}}}
	}

	// 1. Pre-token (firma+aud+exp). Falla → opaco.
	claims, verr := s.PreToken.ValidateChallenge(in.MFAToken)
	if verr != nil {
		return s.invalidVerify(ctx, "expired", start)
	}
	// 2. Single-use: consume (miss → expirado/quemado → opaco).
	ownerID, cerr := s.Chal.Consume(ctx, claims.ChallengeID)
	if cerr != nil {
		return s.invalidVerify(ctx, "expired", start)
	}
	if ownerID == "" || ownerID != claims.Sub {
		return s.invalidVerify(ctx, "expired", start)
	}

	if isBackup {
		return s.verifyBackup(ctx, ownerID, claims, backupCanonical, in.RequestID, mfaDevice(in.IP, in.UserAgent), start)
	}
	return s.verifyTOTP(ctx, ownerID, claims, in.Code, in.RequestID, mfaDevice(in.IP, in.UserAgent), start)
}

// mfaDevice calcula huella para Issue (mismo esquema que login: ip/24 + ua).
func mfaDevice(ip, ua string) auth.Device {
	if ua == "" {
		ua = "mfa-verify"
	}
	if ip == "" {
		ip = "unknown"
	}
	return auth.Device{IPHash: loginSHA256(ip + "/24"), UAHash: loginSHA256(ua)}
}

// verifyTOTP rama TOTP (pasos 3-6 originales).
func (s *MFAService) verifyTOTP(ctx context.Context, ownerID string, claims auth.PreTokenClaims, code, requestID string, dev auth.Device, start time.Time) (*VerifyOutput, error) {
	// 3. Secreto activo + descifrado.
	enc, gerr := s.Secrets.GetActive(ctx, ownerID)
	if gerr != nil {
		return s.invalidVerify(ctx, "expired", start)
	}
	raw, derr := s.Box.Decrypt(ctx, ownerID, enc)
	if derr != nil {
		s.Metrics.IncMFA("verify", "error")
		return nil, fmt.Errorf("decrypt: %w", auth.ErrInfra)
	}

	// 4. TOTP ±1 ConstantTime. Falla → fail + posible burn → opaco.
	counter := auth.NewCounter(time.Now().UTC())
	matched, ok := s.TOTP.Validate(ctx, raw, code, counter)
	if !ok {
		burned, _ := s.Chal.RecordFail(ctx, claims.ChallengeID)
		if burned {
			s.Metrics.IncChallengeBurned("fails")
		}
		s.enqueueMFA(ctx, ownerID, "mfa.failed", map[string]any{"challenge_id": claims.ChallengeID})
		_ = s.Audit.Log(ctx, "mfa.verify", map[string]string{
			"action": "mfa.verify", "user_id": ownerID, "result": "invalid",
		})
		return s.invalidVerify(ctx, "invalid", start)
	}

	// 5. Anti-replay (user,counter) 90s. Reuso → 401 aunque cripto OK.
	if s.Chal.Uncheckable(ctx) {
		s.Metrics.IncMFA("verify", "error")
		return nil, auth.ErrReplayUncheckable
	}
	fresh, rerr := s.Chal.MarkReplay(ctx, ownerID, matched)
	if rerr != nil || !fresh {
		s.Metrics.IncReplayBlocked()
		s.enqueueMFA(ctx, ownerID, "mfa.replay_blocked", map[string]any{"counter": matched})
		_ = s.Audit.Log(ctx, "mfa.verify", map[string]string{
			"action": "mfa.verify", "user_id": ownerID, "result": "replay",
		})
		return s.invalidVerify(ctx, "replay", start)
	}

	// 6. Éxito: sesión + outbox + audit (challenge ya quemado en paso 2).
	return s.verifySuccess(ctx, ownerID, claims, map[string]any{
		"challenge_id": claims.ChallengeID, "counter": matched, "method": "totp",
	}, requestID, "totp", dev, start, -1, false, false)
}

// verifyBackup rama backup (mismo challenge/fails/401, sin oráculo tipo).
func (s *MFAService) verifyBackup(ctx context.Context, ownerID string, claims auth.PreTokenClaims, canonical, requestID string, dev auth.Device, start time.Time) (*VerifyOutput, error) {
	if s.BackupIssuer == nil || s.BackupStore == nil {
		s.Metrics.IncMFA("verify", "error")
		return nil, fmt.Errorf("backup store: %w", auth.ErrInfra)
	}
	hash := s.BackupIssuer.Hash(canonical)
	remaining, cerr := s.BackupStore.ConsumeTx(ctx, ownerID, hash, claims.ChallengeID)
	if cerr != nil {
		// Rotación pepper: reintenta con previo antes de fallar.
		if prev, ok := s.BackupIssuer.HashPrev(canonical); ok {
			var perr error
			remaining, perr = s.BackupStore.ConsumeTx(ctx, ownerID, prev, claims.ChallengeID)
			if perr == nil {
				cerr = nil
			}
		}
	}
	if cerr != nil {
		burned, _ := s.Chal.RecordFail(ctx, claims.ChallengeID)
		if burned {
			s.Metrics.IncChallengeBurned("fails")
		}
		s.enqueueMFA(ctx, ownerID, "mfa.failed", map[string]any{"challenge_id": claims.ChallengeID})
		_ = s.Audit.Log(ctx, "mfa.verify", map[string]string{
			"action": "mfa.verify", "user_id": ownerID, "result": "invalid",
		})
		backupMetrics(s.BackupMetrics).IncBackup("consume", "invalid")
		return s.invalidVerify(ctx, "invalid", start)
	}
	warning := remaining <= 2
	exhausted := remaining == 0
	bm := backupMetrics(s.BackupMetrics)
	bm.IncBackup("consume", "ok")
	bm.SetRemaining(remaining)
	return s.verifySuccess(ctx, ownerID, claims, map[string]any{
		"challenge_id": claims.ChallengeID, "method": "backup", "remaining": remaining,
	}, requestID, "backup", dev, start, remaining, warning, exhausted)
}

// verifySuccess emite sesión + outbox + audit + idempotencia.
func (s *MFAService) verifySuccess(ctx context.Context, ownerID string, claims auth.PreTokenClaims, evt map[string]any, requestID, method string, dev auth.Device, start time.Time, remaining int, warning, exhausted bool) (*VerifyOutput, error) {
	amr := []auth.AMR{auth.AMRPassword, auth.AMRTOTP}
	if method == "backup" {
		amr = []auth.AMR{auth.AMRPassword, auth.AMRBackup}
	}
	pair, serr := s.Sessions.Issue(ctx, auth.SessionRequest{
		UserID: ownerID, Method: auth.MethodPassword, AMR: amr,
		AuthTime: time.Now().UTC(), Device: dev, Roles: []string{"user"},
	})
	if serr != nil {
		s.Metrics.IncMFA("verify", "error")
		return nil, fmt.Errorf("issue session: %w", auth.ErrInfra)
	}
	evt["challenge_id"] = claims.ChallengeID
	s.enqueueMFA(ctx, ownerID, "mfa.verified", evt)
	_ = s.Audit.Log(ctx, "mfa.verify", map[string]string{
		"action": "mfa.verify", "user_id": ownerID, "result": "success",
	})
	s.Metrics.IncMFA("verify", "ok")
	s.Metrics.ObserveVerifyDuration(time.Since(start).Seconds())
	s.putMFAIdem(ctx, requestID, "active")
	return &VerifyOutput{Status: "active", Session: &SessionData{
		AccessToken: pair.AccessJWT, RefreshTokenID: pair.RefreshPlain,
		ExpiresAt: pair.ExpiresAt.Unix(), SID: pair.SID,
	}, Method: method, Remaining: remaining, Warning: warning, Exhausted: exhausted}, nil
}

// invalidVerify aplica jitter 20-50ms + métrica opaca (anti-oráculo).
func (s *MFAService) invalidVerify(ctx context.Context, result string, start time.Time) (*VerifyOutput, error) {
	s.Sleep(mfaJitter())
	_ = s.Audit.Log(ctx, "mfa.verify", map[string]string{
		"action": "mfa.verify", "result": result,
	})
	s.Metrics.IncMFA("verify", result)
	s.Metrics.ObserveVerifyDuration(time.Since(start).Seconds())
	return nil, auth.ErrInvalidMFA
}

func (s *MFAService) putMFAIdem(ctx context.Context, requestID, status string) {
	if s.Idem == nil || requestID == "" {
		return
	}
	_ = s.Idem.Put(ctx, requestID, status, 24*time.Hour)
}
