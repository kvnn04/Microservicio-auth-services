package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/shared"
	"auth-identity-service/internal/domain/user"

	"github.com/google/uuid"
)

// UnlinkInput entrada desvinculación (Step-Up + password si aplica).
type UnlinkInput struct {
	User            AuthUser
	Provider        string
	CurrentPassword string
	RequestID       string
	IP              string
}

// UnlinkOutput resultado (sin PII).
type UnlinkOutput struct {
	Status   string // "unlinked"
	Provider string
}

// LinkedItem item de listado (PII minimizada, SEC-03).
type LinkedItem struct {
	Provider    string `json:"provider"`
	EmailMasked string `json:"email_masked"`
	SubHash     string `json:"sub_hash"`
	LinkedAt    string `json:"linked_at"`
}

// UnlinkService orquesta unlink + list. Solo interfaces de dominio.
type UnlinkService struct {
	Links     user.FederatedLinkStore
	Users     user.UserRepository
	Hasher    auth.PasswordHasher
	Idem      shared.IdempotencyStore
	Audit     shared.AuditLogger
	Metrics   LinkMetricsPort
	Tracer    TracerPort
	StepUpAge time.Duration
}

func NewUnlinkService(
	links user.FederatedLinkStore,
	users user.UserRepository,
	hasher auth.PasswordHasher,
	idem shared.IdempotencyStore,
	audit shared.AuditLogger,
	metrics LinkMetricsPort,
	tracer TracerPort,
	stepUpAge time.Duration,
) *UnlinkService {
	if metrics == nil {
		metrics = NoopLinkMetrics{}
	}
	if tracer == nil {
		tracer = NoopTracer{}
	}
	if audit == nil {
		audit = NoopAudit{}
	}
	if stepUpAge <= 0 {
		stepUpAge = user.StepUpMaxAge
	}
	return &UnlinkService{
		Links: links, Users: users, Hasher: hasher, Idem: idem,
		Audit: audit, Metrics: metrics, Tracer: tracer, StepUpAge: stepUpAge,
	}
}

// Unlink desvincula si quedan ≥1 factores (RN-04). Avisa siempre al dueño.
func (s *UnlinkService) Unlink(ctx context.Context, in UnlinkInput) (*UnlinkOutput, error) {
	ctx, span := s.Tracer.Start(ctx, "UseCase.UnlinkFederated")
	defer span.End()
	p := user.Provider(strings.ToLower(strings.TrimSpace(in.Provider)))
	if !p.IsSupported() {
		return nil, auth.ErrProviderNotSupported
	}
	if _, err := uuid.Parse(in.RequestID); err != nil {
		return nil, &ValidationError{Fields: []FieldError{{Field: "request_id", Reason: "INVALID_FORMAT"}}}
	}
	// Step-Up + password si tiene (token federated:unlink también vale, CU-AUTH-06).
	if !StepUpSatisfied(ctx, auth.ScopeFederatedUnlink) {
		if err := user.RequireFreshAuth(in.User.AuthTime, time.Now().UTC(), s.StepUpAge); err != nil {
			s.Metrics.IncLink(string(p), "unlink", "step_up_required")
			return nil, err
		}
	}
	u, err := s.Users.FindByID(ctx, in.User.ID)
	if err != nil {
		s.Metrics.IncLink(string(p), "unlink", "error")
		return nil, fmt.Errorf("find user: %w", auth.ErrInfra)
	}
	if u.Status != user.StatusActive {
		return nil, auth.ErrAccountUnavailable
	}
	if u.PasswordHash != "" {
		if in.CurrentPassword == "" {
			s.Metrics.IncLink(string(p), "unlink", "step_up_required")
			return nil, user.ErrInvalidStepUp
		}
		ok, verr := s.Hasher.Verify(ctx, in.CurrentPassword, u.PasswordHash)
		if verr != nil || !ok {
			s.Metrics.IncLink(string(p), "unlink", "step_up_required")
			return nil, user.ErrInvalidStepUp
		}
	}
	links, hasPassword, lerr := s.Links.ListByUser(ctx, in.User.ID)
	if lerr != nil {
		s.Metrics.IncLink(string(p), "unlink", "error")
		return nil, fmt.Errorf("list links: %w", auth.ErrInfra)
	}
	if ok, code := user.CanUnlink(hasPassword, len(links), p); !ok {
		_ = code
		s.Metrics.IncLink(string(p), "unlink", "last_factor")
		s.Metrics.IncLastFactorBlocked()
		_ = s.Audit.Log(ctx, "federated.unlink", map[string]string{
			"action": "federated.unlink", "provider": string(p), "result": "last_factor",
		})
		return nil, user.ErrLastAuthFactor
	}
	mail := user.MailPayload{
		To: u.EmailNormalized, Subject: "Cuenta desvinculada",
		Body: "Se desvinculó tu cuenta de Google. Si no fuiste tú, recupera tu acceso aquí.\n",
	}
	outbox := []user.OutboxPayload{{
		EventID: newUUIDv7(), EventType: "federated.unlinked",
		AggregateID: in.User.ID, Topic: "auth.federated.unlinked.v1",
		PayloadJSON: unlinkEventJSON(in.User.ID, string(p), hasPassword, len(links)-1, in.RequestID),
	}}
	linked, uerr := s.Links.UnlinkTx(ctx, in.User.ID, p, outbox, mail)
	if uerr != nil {
		s.Metrics.IncLink(string(p), "unlink", "error")
		return nil, fmt.Errorf("unlink: %w", auth.ErrInfra)
	}
	if !linked {
		s.Metrics.IncLink(string(p), "unlink", "not_linked")
		return nil, user.ErrNotLinked
	}
	if s.Idem != nil {
		_ = s.Idem.Put(ctx, in.RequestID, "unlinked", 24*time.Hour)
	}
	_ = s.Audit.Log(ctx, "federated.unlink", map[string]string{
		"action": "federated.unlink", "provider": string(p), "result": "unlinked",
	})
	s.Metrics.IncLink(string(p), "unlink", "ok")
	return &UnlinkOutput{Status: "unlinked", Provider: string(p)}, nil
}

// List retorna vínculos enmascarados (Bearer normal, sin frescura).
func (s *UnlinkService) List(ctx context.Context, userID string, provider string) ([]LinkedItem, error) {
	links, _, err := s.Links.ListByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list links: %w", auth.ErrInfra)
	}
	items := make([]LinkedItem, 0, len(links))
	for _, l := range links {
		if provider != "" && string(l.Provider) != provider {
			continue
		}
		items = append(items, LinkedItem{
			Provider:    string(l.Provider),
			EmailMasked: maskEmail(l.EmailAtLink),
			SubHash:     linkSubHash(l.Sub)[:8],
			LinkedAt:    l.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}
	s.Metrics.IncLink(provider, "list", "ok")
	return items, nil
}

// maskEmail enmascara el local salvo 1 char: u***@dominio (SEC-03).
func maskEmail(email string) string {
	at := strings.Index(email, "@")
	if at <= 0 {
		return "***"
	}
	return email[:1] + "***" + email[at:]
}

func unlinkEventJSON(userID, provider string, hasPassword bool, left int, requestID string) []byte {
	b, _ := json.Marshal(map[string]any{
		"user_id": userID, "provider": provider,
		"factors_left": left, "request_id": requestID,
	})
	_ = hasPassword
	return b
}
