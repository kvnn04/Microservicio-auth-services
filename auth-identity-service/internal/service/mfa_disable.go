package service

import (
	"context"
	"fmt"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/user"

	"github.com/google/uuid"
)

// DisableInput entrada disable (Step-Up; último factor bloquea).
type DisableInput struct {
	User      AuthUser
	RequestID string
}

// DisableOutput resultado.
type DisableOutput struct {
	Status string // "disabled"
}

// Disable apaga MFA si quedan factores (password o federado).
func (s *MFAService) Disable(ctx context.Context, in DisableInput) (*DisableOutput, error) {
	ctx, span := s.Tracer.Start(ctx, "UseCase.MFADisable")
	defer span.End()
	if err := s.fresh(in.User); err != nil {
		s.Metrics.IncMFA("disable", "step_up_required")
		return nil, err
	}
	u, err := s.activeUser(ctx, in.User.ID)
	if err != nil {
		return nil, err
	}
	if _, err := uuid.Parse(in.RequestID); err != nil {
		return nil, &ValidationError{Fields: []FieldError{{Field: "request_id", Reason: "INVALID_FORMAT"}}}
	}
	links, hasPassword := s.linkFactors(ctx, u.ID)
	// Al quitar MFA quedan password+federados: si no queda ninguno → último.
	if user.CountFactors(hasPassword, len(links)) < 1 {
		s.Metrics.IncMFA("disable", "last_factor")
		_ = s.Audit.Log(ctx, "mfa.disable", map[string]string{
			"action": "mfa.disable", "user_id": u.ID, "result": "last_factor",
		})
		return nil, user.ErrLastAuthFactor
	}
	if s.BackupStore != nil {
		_ = s.BackupStore.BurnAll(ctx, u.ID)
	}
	if derr := s.Secrets.DisableTx(ctx, u.ID); derr != nil {
		s.Metrics.IncMFA("disable", "error")
		return nil, fmt.Errorf("disable: %w", auth.ErrInfra)
	}
	s.enqueueMFA(ctx, u.ID, "mfa.disabled", map[string]any{})
	_ = s.Audit.Log(ctx, "mfa.disable", map[string]string{
		"action": "mfa.disable", "user_id": u.ID, "result": "disabled",
	})
	s.Metrics.IncMFA("disable", "ok")
	return &DisableOutput{Status: "disabled"}, nil
}

// StatusOutput estado (Bearer normal, sin frescura).
type StatusOutput struct {
	Enabled   bool     `json:"enabled"`
	Methods   []string `json:"methods"`
	Remaining int      `json:"backup_remaining"`
	Warning   bool     `json:"backup_warning"`
}

// Status lee secreto activo + restantes (sin valores planos jamás).
func (s *MFAService) Status(ctx context.Context, userID string) (*StatusOutput, error) {
	if _, err := s.Secrets.GetActive(ctx, userID); err != nil {
		return &StatusOutput{Enabled: false, Methods: []string{}, Remaining: 0}, nil
	}
	remaining := 0
	if s.BackupStore != nil {
		if n, cerr := s.BackupStore.CountRemaining(ctx, userID); cerr == nil {
			remaining = n
		}
	}
	return &StatusOutput{Enabled: true, Methods: []string{"totp"},
		Remaining: remaining, Warning: remaining <= 2}, nil
}

func (s *MFAService) linkFactors(ctx context.Context, userID string) ([]user.FederatedIdentity, bool) {
	if s.Links == nil {
		// Sin store de links: asume sin federados (conservador para disable:
		// CanUnlink con password decide; sin password → último factor).
		if u, err := s.Users.FindByID(ctx, userID); err == nil && u != nil {
			return nil, u.PasswordHash != ""
		}
		return nil, false
	}
	links, hasPassword, err := s.Links.ListByUser(ctx, userID)
	if err != nil {
		return nil, false
	}
	return links, hasPassword
}
