package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/shared"
	"auth-identity-service/internal/domain/user"

	"github.com/google/uuid"
)

// LinkMetricsPort telemetría CU-REG-06 (T-05). Sin SDK directo.
type LinkMetricsPort interface {
	IncLink(provider, op, result string)
	IncLastFactorBlocked()
	IncLinkStateFailure(reason string)
}

// NoopLinkMetrics default sin telemetría.
type NoopLinkMetrics struct{}

func (NoopLinkMetrics) IncLink(string, string, string) {}
func (NoopLinkMetrics) IncLastFactorBlocked()           {}
func (NoopLinkMetrics) IncLinkStateFailure(string)     {}

// AuthUser identidad del Bearer (middleware require_auth la inyecta).
type AuthUser struct {
	ID       string
	AuthTime time.Time
}

// LinkInitiateInput entrada initiate (Step-Up + password si aplica).
type LinkInitiateInput struct {
	User            AuthUser
	Provider        string
	CurrentPassword string
	RequestID       string
	IP              string
}

// LinkInitiateOutput URL IdP + state (SPA abre popup, no 302).
type LinkInitiateOutput struct {
	URL       string
	State     string
	ExpiresIn int
}

// LinkCallbackInput entrada callback (misma sesión).
type LinkCallbackInput struct {
	User      AuthUser
	Provider  string
	Code      string
	State     string
	RequestID string
	IP        string
}

// LinkCallbackOutput nunca expone sub/plano.
type LinkCallbackOutput struct {
	Status   string // "linked" | "already_linked"
	Provider string
}

// LinkService orquesta initiate/callback. Solo interfaces de dominio.
type LinkService struct {
	IdPs      auth.IdentityProviderClient
	Links     user.FederatedLinkStore
	States    user.LinkStateStore
	Users     user.UserRepository
	Hasher    auth.PasswordHasher
	Outbox    OutboxEnqueuer
	Throttle  user.NotifyThrottle
	Idem      shared.IdempotencyStore
	Audit     shared.AuditLogger
	Metrics   LinkMetricsPort
	Tracer    TracerPort
	LinkCallbackURI string
	MaxLinked int
	StepUpAge time.Duration
}

func NewLinkService(
	idps auth.IdentityProviderClient,
	links user.FederatedLinkStore,
	states user.LinkStateStore,
	users user.UserRepository,
	hasher auth.PasswordHasher,
	outbox OutboxEnqueuer,
	throttle user.NotifyThrottle,
	idem shared.IdempotencyStore,
	audit shared.AuditLogger,
	metrics LinkMetricsPort,
	tracer TracerPort,
	linkCallbackURI string,
	maxLinked int,
	stepUpAge time.Duration,
) *LinkService {
	if metrics == nil {
		metrics = NoopLinkMetrics{}
	}
	if tracer == nil {
		tracer = NoopTracer{}
	}
	if audit == nil {
		audit = NoopAudit{}
	}
	if maxLinked <= 0 {
		maxLinked = user.MaxLinkedProviders
	}
	if stepUpAge <= 0 {
		stepUpAge = user.StepUpMaxAge
	}
	return &LinkService{
		IdPs: idps, Links: links, States: states, Users: users, Hasher: hasher,
		Outbox: outbox, Throttle: throttle, Idem: idem, Audit: audit,
		Metrics: metrics, Tracer: tracer, LinkCallbackURI: linkCallbackURI,
		MaxLinked: maxLinked, StepUpAge: stepUpAge,
	}
}

// stepUp valida frescura + password si el usuario tiene (RN-03, genérico).
func (s *LinkService) stepUp(ctx context.Context, au AuthUser, password string) (*user.User, error) {
	if err := user.RequireFreshAuth(au.AuthTime, time.Now().UTC(), s.StepUpAge); err != nil {
		return nil, err
	}
	u, err := s.Users.FindByID(ctx, au.ID)
	if err != nil {
		return nil, fmt.Errorf("find user: %w", auth.ErrInfra)
	}
	if u.Status != user.StatusActive {
		return nil, auth.ErrAccountUnavailable
	}
	if u.PasswordHash != "" {
		if password == "" {
			return nil, user.ErrInvalidStepUp
		}
		ok, verr := s.Hasher.Verify(ctx, password, u.PasswordHash)
		if verr != nil || !ok {
			return nil, user.ErrInvalidStepUp
		}
	}
	return u, nil
}

// Initiate valida Step-Up y crea el estado link (sin tocar IdP aún).
func (s *LinkService) Initiate(ctx context.Context, in LinkInitiateInput) (*LinkInitiateOutput, error) {
	ctx, span := s.Tracer.Start(ctx, "UseCase.LinkFederatedInitiate")
	defer span.End()
	p := user.Provider(strings.ToLower(strings.TrimSpace(in.Provider)))
	if !p.IsSupported() {
		return nil, auth.ErrProviderNotSupported
	}
	if _, err := uuid.Parse(in.RequestID); err != nil {
		return nil, &ValidationError{Fields: []FieldError{{Field: "request_id", Reason: "INVALID_FORMAT"}}}
	}
	u, serr := s.stepUp(ctx, in.User, in.CurrentPassword)
	if serr != nil {
		s.Metrics.IncLink(string(p), "initiate", s.stepUpResult(serr))
		return nil, serr
	}
	_ = u
	authURL, verifier, err := s.IdPs.BuildAuthorizeURL(ctx, auth.AuthorizeReq{
		Provider: p, RedirectURI: s.LinkCallbackURI,
		Scopes: []string{"openid", "email", "profile"},
	})
	if err != nil {
		return nil, fmt.Errorf("build authorize: %w", auth.ErrInfra)
	}
	if serr := s.States.SaveLinkState(ctx, authURL.State, user.LinkState{
		UserID: in.User.ID, Nonce: authURL.Nonce, Verifier: verifier,
		IPHash: linkIPHash(in.IP), CreatedAt: time.Now().UTC().Unix(),
	}); serr != nil {
		s.Metrics.IncLinkStateFailure("save")
		return nil, fmt.Errorf("save link state: %w", auth.ErrInfra)
	}
	s.Metrics.IncLink(string(p), "initiate", "ok")
	return &LinkInitiateOutput{URL: authURL.URL, State: authURL.State, ExpiresIn: 600}, nil
}

func (s *LinkService) stepUpResult(err error) string {
	if errors.Is(err, user.ErrStepUpRequired) {
		return "step_up_required"
	}
	return "error"
}

// Callback resuelve el link con user-match estricto (anti-fijación).
func (s *LinkService) Callback(ctx context.Context, in LinkCallbackInput) (*LinkCallbackOutput, error) {
	start := time.Now()
	ctx, span := s.Tracer.Start(ctx, "UseCase.LinkFederatedCallback")
	defer span.End()
	p := user.Provider(strings.ToLower(strings.TrimSpace(in.Provider)))
	if !p.IsSupported() {
		return nil, auth.ErrProviderNotSupported
	}
	if in.Code == "" || in.State == "" {
		s.Metrics.IncLink(string(p), "link", "invalid_state")
		return nil, auth.ErrInvalidState
	}
	if _, err := uuid.Parse(in.RequestID); err != nil {
		return nil, &ValidationError{Fields: []FieldError{{Field: "request_id", Reason: "INVALID_FORMAT"}}}
	}
	// Step-Up en callback: solo frescura (el password se probó en initiate,
	// misma ventana de 5min y state ligado al usuario).
	if err := user.RequireFreshAuth(in.User.AuthTime, time.Now().UTC(), s.StepUpAge); err != nil {
		s.Metrics.IncLink(string(p), "link", "step_up_required")
		return nil, err
	}
	if u, uerr := s.Users.FindByID(ctx, in.User.ID); uerr != nil || u == nil || u.Status != user.StatusActive {
		if uerr == nil {
			s.Metrics.IncLink(string(p), "link", "error")
			return nil, auth.ErrAccountUnavailable
		}
		s.Metrics.IncLink(string(p), "link", "error")
		return nil, fmt.Errorf("find user: %w", auth.ErrInfra)
	}
	if s.Idem != nil {
		if v, found, _ := s.Idem.Get(ctx, in.RequestID); found {
			return &LinkCallbackOutput{Status: v, Provider: string(p)}, nil
		}
	}
	st, cerr := s.States.ConsumeLinkState(ctx, in.State)
	if cerr != nil {
		s.Metrics.IncLinkStateFailure("consume")
		s.Metrics.IncLink(string(p), "link", "invalid_state")
		if errors.Is(cerr, user.ErrNotFound) {
			return nil, auth.ErrInvalidState
		}
		return nil, fmt.Errorf("consume link state: %w", auth.ErrInfra)
	}
	if st.UserID == "" || st.UserID != in.User.ID {
		s.Metrics.IncLink(string(p), "link", "invalid_state")
		_ = s.Audit.Log(ctx, "federated.link", map[string]string{
			"action": "federated.link", "provider": string(p), "result": "user_mismatch",
		})
		return nil, auth.ErrInvalidState
	}
	t0 := time.Now()
	tokens, xerr := s.IdPs.ExchangeCode(ctx, p, in.Code, st.Verifier, s.LinkCallbackURI)
	_ = time.Since(t0)
	if xerr != nil {
		if errors.Is(xerr, auth.ErrIDPUnavailable) {
			s.Metrics.IncLink(string(p), "link", "idp_unavailable")
			return nil, auth.ErrIDPUnavailable
		}
		s.Metrics.IncLink(string(p), "link", "invalid_token")
		return nil, auth.ErrInvalidCode
	}
	claims, verr := s.IdPs.VerifyIDToken(ctx, p, tokens.IDToken, st.Nonce)
	if verr != nil {
		s.Metrics.IncLink(string(p), "link", "invalid_token")
		return nil, auth.ErrInvalidToken
	}
	subHash := linkSubHash(claims.Sub)
	fi, ferr := user.NewFederatedIdentity(p, claims.Sub, in.User.ID, claims.Email)
	if ferr != nil {
		s.Metrics.IncLink(string(p), "link", "error")
		return nil, fmt.Errorf("identity: %w", auth.ErrInfra)
	}
	fi.Iss = claims.Iss
	mail := user.MailPayload{
		To: claims.Email, Subject: "Nueva cuenta vinculada",
		Body: "Vinculaste tu cuenta de Google. Si no fuiste tú, cambia tu contraseña.\n",
	}
	events := []user.OutboxPayload{{
		EventID: newUUIDv7(), EventType: "federated.linked",
		AggregateID: in.User.ID, Topic: "auth.federated.linked.v1",
		PayloadJSON: linkEventJSON(in.User.ID, string(p), subHash, in.RequestID),
	}}
	if lerr := s.Links.LinkTx(ctx, fi, events, []user.MailPayload{mail}); lerr != nil {
		switch {
		case errors.Is(lerr, user.ErrAlreadyLinkedSelf):
			s.putLinkIdem(ctx, in.RequestID, "already_linked")
			s.Metrics.IncLink(string(p), "link", "already_linked")
			return &LinkCallbackOutput{Status: "already_linked", Provider: string(p)}, nil
		case errors.Is(lerr, user.ErrProviderTaken):
			s.Metrics.IncLink(string(p), "link", "provider_taken")
			return nil, lerr
		case errors.Is(lerr, user.ErrCollisionForeign):
			s.collisionNotify(ctx, p, in.User.ID, claims, subHash, in)
			s.Metrics.IncLink(string(p), "link", "collision")
			return nil, lerr
		default:
			s.Metrics.IncLink(string(p), "link", "error")
			return nil, fmt.Errorf("link: %w", auth.ErrInfra)
		}
	}
	s.putLinkIdem(ctx, in.RequestID, "linked")
	_ = s.Audit.Log(ctx, "federated.link", map[string]string{
		"action": "federated.link", "provider": string(p),
		"sub_hash": subHash, "result": "linked",
	})
	s.Metrics.IncLink(string(p), "link", "ok")
	_ = start
	return &LinkCallbackOutput{Status: "linked", Provider: string(p)}, nil
}

// collisionNotify avisa a ambas puntas sin PII cruzada (throttle 1/h por sub).
func (s *LinkService) collisionNotify(ctx context.Context, p user.Provider, requesterID string, claims auth.OIDClaims, subHash string, in LinkCallbackInput) {
	_ = s.Audit.Log(ctx, "federated.link_collision", map[string]string{
		"action": "federated.link_collision", "provider": string(p),
		"sub_hash": subHash, "result": "collision",
	})
	if s.Outbox == nil {
		return
	}
	allowed := true
	if s.Throttle != nil {
		if ok, terr := s.Throttle.AllowOwnerNotify(ctx, subHash); terr == nil {
			allowed = ok
		}
	}
	if !allowed {
		return
	}
	// Owner para notify: lookup por sub (sin exponerlo al requester).
	ownerID := ""
	if _, owner, ferr := s.Links.FindByProviderSub(ctx, p, claims.Sub); ferr == nil && owner != nil {
		ownerID = owner.ID
	}
	payload, _ := json.Marshal(map[string]any{
		"provider": string(p), "sub_hash": "sha256:" + subHash,
		"requester_user_id": requesterID, "owner_user_id": ownerID,
		"ip_hash": "sha256:" + linkIPHash(in.IP),
	})
	_ = s.Outbox.Enqueue(ctx, []user.OutboxPayload{{
		EventID: newUUIDv7(), EventType: "security.federated_link_collision",
		AggregateID: subHash, Topic: "auth.security.federated_link_collision.v1",
		PayloadJSON: payload,
	}})
}

func (s *LinkService) putLinkIdem(ctx context.Context, requestID, status string) {
	if s.Idem == nil || requestID == "" {
		return
	}
	_ = s.Idem.Put(ctx, requestID, status, 24*time.Hour)
}

func linkIPHash(ip string) string {
	h := sha256.Sum256([]byte(ip + "/24"))
	return hex.EncodeToString(h[:])
}

func linkSubHash(sub string) string {
	h := sha256.Sum256([]byte(sub))
	return hex.EncodeToString(h[:])
}

func linkEventJSON(userID, provider, subHash, requestID string) []byte {
	b, _ := json.Marshal(map[string]any{
		"user_id": userID, "provider": provider,
		"sub_hash": "sha256:" + subHash, "request_id": requestID,
	})
	return b
}
