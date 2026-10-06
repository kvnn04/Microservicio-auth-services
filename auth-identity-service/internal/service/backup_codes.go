package service

import (
	"context"
	"fmt"

	"auth-identity-service/internal/domain/auth"
)

// backup_codes.go (CU-AUTH-03): generación, regeneración y consumo.
// Los planos existen solo en memoria del request + response TLS (1 exhibición).

// BackupMetricsPort telemetría CU-AUTH-03 (inyectable, nil-safe).
type BackupMetricsPort interface {
	IncBackup(op, result string)
	SetRemaining(remaining int)
}

// NoopBackupMetrics default sin telemetría.
type NoopBackupMetrics struct{}

func (NoopBackupMetrics) IncBackup(string, string) {}
func (NoopBackupMetrics) SetRemaining(int)         {}

func backupMetrics(m BackupMetricsPort) BackupMetricsPort {
	if m == nil {
		return NoopBackupMetrics{}
	}
	return m
}

// generateBackupSet genera 10 únicos (reintenta colisión en memoria),
// persiste hashes y retorna planos UNA vez. supersede quema previos.
func (s *MFAService) generateBackupSet(ctx context.Context, userID string, supersede bool) (plains []string, superseded int, err error) {
	if s.BackupIssuer == nil || s.BackupStore == nil {
		return nil, 0, fmt.Errorf("backup store: %w", auth.ErrInfra)
	}
	seen := map[string]bool{}
	var hashes []string
	for len(plains) < auth.BackupCount {
		p, h, gerr := s.BackupIssuer.Generate(ctx)
		if gerr != nil {
			return nil, 0, gerr
		}
		if seen[h] {
			continue // colisión CSPRNG en memoria → regenera ese código.
		}
		seen[h] = true
		plains = append(plains, p)
		hashes = append(hashes, h)
	}
	superseded, serr := s.BackupStore.GenerateTx(ctx, userID, hashes, supersede)
	if serr != nil {
		return nil, 0, serr
	}
	return plains, superseded, nil
}

// RegenerateInput entrada regenerate (Step-Up fresco).
type RegenerateInput struct {
	User      AuthUser
	RequestID string
}

// RegenerateOutput 10 nuevos (quema previos aunque intactos, RN-01/§4.5).
type RegenerateOutput struct {
	Codes     []string
	Remaining int
}

// Regenerate exige Step-Up y re-exhibe 10 nuevos (viejos superseded).
func (s *MFAService) Regenerate(ctx context.Context, in RegenerateInput) (*RegenerateOutput, error) {
	ctx, span := s.Tracer.Start(ctx, "UseCase.MFARegenerate")
	defer span.End()
	if err := s.freshStepUp(ctx, in.User, auth.ScopeBackupRegen); err != nil {
		s.Metrics.IncMFA("regenerate", "step_up_required")
		return nil, err
	}
	u, err := s.activeUser(ctx, in.User.ID)
	if err != nil {
		return nil, err
	}
	if _, serr := s.Secrets.GetActive(ctx, u.ID); serr != nil {
		// Sin TOTP activo no hay qué respaldar.
		s.Metrics.IncMFA("regenerate", "invalid")
		return nil, auth.ErrNoStaged
	}
	plains, _, gerr := s.generateBackupSet(ctx, u.ID, true)
	if gerr != nil {
		s.Metrics.IncMFA("regenerate", "error")
		return nil, fmt.Errorf("regenerate: %w", auth.ErrInfra)
	}
	remaining := auth.BackupCount
	if s.BackupStore != nil {
		if n, cerr := s.BackupStore.CountRemaining(ctx, u.ID); cerr == nil {
			remaining = n
		}
	}
	_ = s.Audit.Log(ctx, "backup.regenerate", map[string]string{
		"action": "backup.regenerate", "user_id": u.ID, "result": "ok",
	})
	s.Metrics.IncMFA("regenerate", "ok")
	return &RegenerateOutput{Codes: plains, Remaining: remaining}, nil
}
