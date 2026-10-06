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

// FederatedMetricsPort telemetría CU-REG-04 (T-05). Sin SDK directo.
type FederatedMetricsPort interface {
	IncFederated(provider, result string)
	ObserveFederatedDuration(seconds float64)
	ObserveIDPLatency(op string, seconds float64)
	IncCollision(provider string)
}

// NoopFederatedMetrics default sin telemetría.
type NoopFederatedMetrics struct{}

func (NoopFederatedMetrics) IncFederated(string, string)           {}
func (NoopFederatedMetrics) ObserveFederatedDuration(float64)     {}
func (NoopFederatedMetrics) ObserveIDPLatency(string, float64)     {}
func (NoopFederatedMetrics) IncCollision(string)                  {}

// AuthorizeInput entrada authorize (front pide URL IdP).
type AuthorizeInput struct {
	Provider       string
	ReturnTo       string
	IP             string
	TermsAccepted  bool
	TermsVersion   string
	PrivacyVersion string
}

// AuthorizeOutput URL + state (el handler setea cookie 302).
type AuthorizeOutput struct {
	URL   string
	State string
}

// CallbackInput entrada callback (code/state de Google o error=access_denied).
type CallbackInput struct {
	Provider   string
	Code       string
	State      string
	IdpError   string
	RequestID  string
	IP         string
	UserAgent  string
	HasBearer  bool
}

// SessionData sesión emitida (CU-AUTH-04 enterprise: Access Ed25519 + Refresh opaco).
type SessionData struct {
	AccessToken    string
	RefreshTokenID string
	ExpiresAt      int64
	SID            string
}

// CallbackOutput nunca expone sub/email/tokens IdP.
type CallbackOutput struct {
	Status   string // "active" | "pending_verification"
	Provider string
	Session  *SessionData // solo si active
}

// RegisterFederatedService orquesta CU-REG-04. Solo interfaces de dominio.
type RegisterFederatedService struct {
	IdPs         auth.IdentityProviderClient
	Fed          user.FederatedRepository
	States       auth.FederatedStateStore
	VerifyStore  auth.VerificationStore
	PairIssuer   VerificationPairIssuer
	Sessions     auth.SessionIssuer
	Outbox       OutboxEnqueuer
	Throttle     user.NotifyThrottle
	Idem         shared.IdempotencyStore
	Audit        shared.AuditLogger
	Metrics      FederatedMetricsPort
	Tracer       TracerPort
	// CU-REG-05: Legal exige DB (fail-closed); nil = skip (tests).
	Legal        shared.LegalVersionProvider
	Consents     ConsentMetricsPort
	TermsVersion string
	RequireTerms bool
}

func NewRegisterFederatedService(
	idps auth.IdentityProviderClient,
	fed user.FederatedRepository,
	states auth.FederatedStateStore,
	verifyStore auth.VerificationStore,
	pairIssuer VerificationPairIssuer,
	sessions auth.SessionIssuer,
	outbox OutboxEnqueuer,
	throttle user.NotifyThrottle,
	idem shared.IdempotencyStore,
	audit shared.AuditLogger,
	metrics FederatedMetricsPort,
	tracer TracerPort,
	termsVersion string,
	requireTerms bool,
) *RegisterFederatedService {
	if metrics == nil {
		metrics = NoopFederatedMetrics{}
	}
	if tracer == nil {
		tracer = NoopTracer{}
	}
	if audit == nil {
		audit = NoopAudit{}
	}
	return &RegisterFederatedService{
		IdPs: idps, Fed: fed, States: states, VerifyStore: verifyStore,
		PairIssuer: pairIssuer, Sessions: sessions, Outbox: outbox,
		Throttle: throttle, Idem: idem, Audit: audit,
		Metrics: metrics, Tracer: tracer,
		TermsVersion: termsVersion, RequireTerms: requireTerms,
	}
}

// validReturnTo: allowlist relativos (/app, /login...). Sin open-redirect.
func validReturnTo(s string) string {
	if s == "" {
		return "/app"
	}
	if !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") {
		return "/app"
	}
	if strings.Contains(s, "://") {
		return "/app"
	}
	return s
}

// Authorize genera el flujo (state/nonce/PKCE en adapter, estado en Redis).
func (s *RegisterFederatedService) Authorize(ctx context.Context, in AuthorizeInput) (*AuthorizeOutput, error) {
	p := user.Provider(strings.ToLower(strings.TrimSpace(in.Provider)))
	if !p.IsSupported() {
		return nil, auth.ErrProviderNotSupported
	}
	if s.RequireTerms && !in.TermsAccepted {
		return nil, auth.ErrTermsRequired
	}
	// CU-REG-05: consentimiento pre-302 (sin state en Redis si falla).
	if s.Legal != nil {
		if ferr := CheckConsentFast(in.TermsAccepted, in.TermsVersion, in.PrivacyVersion); ferr != nil {
			return nil, ConsentValidationError(ferr)
		}
		activeT, activeP, gerr := s.Legal.GetActive(ctx)
		if gerr != nil {
			return nil, fmt.Errorf("legal versions: %w", auth.ErrInfra)
		}
		if cerr := CheckConsentAgainstActive(in.TermsVersion, in.PrivacyVersion, activeT, activeP); cerr != nil {
			consentMetrics(s.Consents).IncConsentRejected("outdated")
			return nil, cerr
		}
	}
	t0 := time.Now()
	authURL, verifier, err := s.IdPs.BuildAuthorizeURL(ctx, auth.AuthorizeReq{
		Provider: p, Scopes: []string{"openid", "email", "profile"},
		ReturnTo: validReturnTo(in.ReturnTo),
	})
	s.Metrics.ObserveIDPLatency("build_authorize", time.Since(t0).Seconds())
	if err != nil {
		return nil, fmt.Errorf("build authorize: %w", auth.ErrInfra)
	}
	if authURL.State == "" || verifier == "" {
		return nil, fmt.Errorf("idp state: %w", auth.ErrInfra)
	 }
	if serr := s.States.SaveState(ctx, authURL.State, auth.FederatedState{
		Nonce: authURL.Nonce, Verifier: verifier,
		IPHash: sha256HexShort(in.IP), ReturnTo: validReturnTo(in.ReturnTo),
		CreatedAt: time.Now().UTC().Unix(),
		TermsVersion: in.TermsVersion, PrivacyVersion: in.PrivacyVersion,
	}); serr != nil {
		return nil, fmt.Errorf("save state: %w", auth.ErrInfra)
	}
	return &AuthorizeOutput{URL: authURL.URL, State: authURL.State}, nil
}

// Callback resuelve el code de Google. Nunca crea antes de validar firma.
func (s *RegisterFederatedService) Callback(ctx context.Context, in CallbackInput) (*CallbackOutput, error) {
	start := time.Now()
	ctx, span := s.Tracer.Start(ctx, "UseCase.RegisterFederated")
	defer span.End()
	p := user.Provider(strings.ToLower(strings.TrimSpace(in.Provider)))
	if !p.IsSupported() {
		return nil, auth.ErrProviderNotSupported
	}
	if in.HasBearer {
		return nil, auth.ErrUseLinkFlow // derivar a CU-REG-06, no linkear aquí.
	}
	if in.IdpError == "access_denied" {
		s.Metrics.IncFederated(string(p), "cancelled")
		return nil, auth.ErrFederatedCancelled
	}
	if in.Code == "" || in.State == "" {
		s.Metrics.IncFederated(string(p), "invalid_state")
		return nil, auth.ErrInvalidState
	}
	if _, err := uuid.Parse(in.RequestID); err != nil {
		return nil, &ValidationError{Fields: []FieldError{{Field: "request_id", Reason: "INVALID_FORMAT"}}}
	}
	if s.Idem != nil {
		if v, found, _ := s.Idem.Get(ctx, in.RequestID); found {
			s.Metrics.ObserveFederatedDuration(time.Since(start).Seconds())
			return &CallbackOutput{Status: v, Provider: string(p)}, nil
		}
	}

	// 1. Estado (un solo uso; fail-closed si Redis cae).
	st, serr := s.States.ConsumeState(ctx, in.State)
	if serr != nil {
		s.Metrics.IncFederated(string(p), "invalid_state")
		if errors.Is(serr, user.ErrNotFound) {
			return nil, auth.ErrInvalidState
		}
		return nil, fmt.Errorf("consume state: %w", auth.ErrInfra)
	}

	// CU-REG-05: revalida versiones del authorize (rotación 10min) antes del canje.
	if s.Legal != nil && st.TermsVersion != "" {
		activeT, activeP, gerr := s.Legal.GetActive(ctx)
		if gerr != nil {
			s.Metrics.IncFederated(string(p), "error")
			return nil, fmt.Errorf("legal versions: %w", auth.ErrInfra)
		}
		if cerr := CheckConsentAgainstActive(st.TermsVersion, st.PrivacyVersion, activeT, activeP); cerr != nil {
			consentMetrics(s.Consents).IncConsentRejected("outdated")
			s.Metrics.IncFederated(string(p), "invalid_token")
			return nil, cerr
		}
	}

	// 2. Canje (sin DB aún).
	t0 := time.Now()
	tokens, xerr := s.IdPs.ExchangeCode(ctx, p, in.Code, st.Verifier, "")
	s.Metrics.ObserveIDPLatency("token", time.Since(t0).Seconds())
	if xerr != nil {
		if errors.Is(xerr, auth.ErrIDPUnavailable) {
			s.Metrics.IncFederated(string(p), "idp_unavailable")
			return nil, auth.ErrIDPUnavailable
		}
		s.Metrics.IncFederated(string(p), "invalid_token")
		return nil, auth.ErrInvalidCode
	}

	// 3. Verifica firma + claims + nonce.
	t1 := time.Now()
	claims, verr := s.IdPs.VerifyIDToken(ctx, p, tokens.IDToken, st.Nonce)
	s.Metrics.ObserveIDPLatency("jwks", time.Since(t1).Seconds())
	if verr != nil {
		s.Metrics.IncFederated(string(p), "invalid_token")
		return nil, auth.ErrInvalidToken
	}

	// 4. Normaliza email (malformado/ausente → 400 sin tocar DB de negocio).
	normalized, _, nerr := user.Normalize(claims.Email)
	if nerr != nil || claims.Email == "" {
		s.Metrics.IncFederated(string(p), "invalid_token")
		return nil, auth.ErrIDPEmailMissing
	}
	subHash := sha256HexShort(claims.Sub)
	emailHash := sha256HexShort(normalized)

	// 5. Hit (provider,sub) → login federado.
	if ident, u, ferr := s.Fed.FindByProviderSub(ctx, p, claims.Sub); ferr == nil && ident != nil && u != nil {
		return s.login(ctx, p, u, "linked_login", in, start, subHash, emailHash)
	}

	// 6. Miss → ¿colisión de email? (anti-takeover: jamás fusionar).
	if existing, eerr := s.Fed.FindUserByEmailNormalized(ctx, normalized); eerr == nil && existing != nil {
		s.collision(ctx, p, existing.ID, normalized, emailHash, subHash, claims.Sub, in)
		s.Metrics.IncFederated(string(p), "link_required")
		s.Metrics.IncCollision(string(p))
		s.Metrics.ObserveFederatedDuration(time.Since(start).Seconds())
		return nil, auth.ErrLinkRequired
	}

	// 7. Alta: bifurca por email_verified (RN-02).
	verified := claims.IsVerified()
	now := time.Now().UTC()
	uid := newUUIDv7()
	u, uerr := user.NewFederatedUser(uid, claims.Email, normalized,
		s.TermsVersion, s.TermsVersion, "federated_"+string(p), verified, now)
	if uerr != nil {
		s.Metrics.IncFederated(string(p), "error")
		return nil, fmt.Errorf("new user: %w", auth.ErrInfra)
	}
	fed, ferr := user.NewFederatedIdentity(p, claims.Sub, uid, normalized)
	if ferr != nil {
		s.Metrics.IncFederated(string(p), "error")
		return nil, fmt.Errorf("new identity: %w", auth.ErrInfra)
	}
	fed.Iss = claims.Iss
	events, mail := s.creationEvents(p, u, fed, emailHash, normalized, verified, in.RequestID, now)
	regCtx := user.RegistrationContext{
		IPHash: sha256HexShort(in.IP), UAHash: sha256HexShort(in.UserAgent),
		Source: "federated_" + string(p), RequestID: in.RequestID,
	}
	if cerr := s.Fed.CreateUserWithFederation(ctx, u, fed, events, mail, regCtx); cerr != nil {
		if errors.Is(cerr, user.ErrAlreadyLinked) {
			// Carrera: otro callback vinculó el sub → login.
			if _, u2, ferr2 := s.Fed.FindByProviderSub(ctx, p, claims.Sub); ferr2 == nil && u2 != nil {
				return s.login(ctx, p, u2, "linked_login", in, start, subHash, emailHash)
			}
		}
		if errors.Is(cerr, user.ErrEmailCollision) {
			s.collision(ctx, p, "", normalized, emailHash, subHash, claims.Sub, in)
			s.Metrics.IncFederated(string(p), "link_required")
			s.Metrics.IncCollision(string(p))
			s.Metrics.ObserveFederatedDuration(time.Since(start).Seconds())
			return nil, auth.ErrLinkRequired
		}
		s.Metrics.IncFederated(string(p), "error")
		return nil, fmt.Errorf("create federated: %w", auth.ErrInfra)
	}

	if verified {
		sess, _ := s.issueSession(ctx, uid, in)
		s.putIdem(ctx, in.RequestID, "active")
		_ = s.Audit.Log(ctx, "federated.register", map[string]string{
			"action": "federated.register", "provider": string(p),
			"sub_hash": subHash, "email_hash": emailHash, "result": "active",
		})
		s.Metrics.IncFederated(string(p), "active")
		cm := consentMetrics(s.Consents)
		cm.IncConsentRecorded("terms", "federated_"+string(p))
		cm.IncConsentRecorded("privacy", "federated_"+string(p))
		s.Metrics.ObserveFederatedDuration(time.Since(start).Seconds())
		return &CallbackOutput{Status: "active", Provider: string(p), Session: sess}, nil
	}
	// PENDING: encola OTP CU-REG-02 (link + código) vía VerifyStore.
	if s.VerifyStore != nil && s.PairIssuer != nil {
		_, th, _, oh, gerr := s.PairIssuer.GeneratePair()
		if gerr == nil {
			_ = s.VerifyStore.Register(ctx, &auth.VerificationRecord{
				UserID: uid, TokenHash: th, OTPHash: oh,
				ExpiresAt: now.Add(auth.VerifyTTL),
			})
		}
	}
	s.putIdem(ctx, in.RequestID, "pending_verification")
	_ = s.Audit.Log(ctx, "federated.register", map[string]string{
		"action": "federated.register", "provider": string(p),
		"sub_hash": subHash, "email_hash": emailHash, "result": "pending",
	})
	s.Metrics.IncFederated(string(p), "pending")
	cm := consentMetrics(s.Consents)
	cm.IncConsentRecorded("terms", "federated_"+string(p))
	cm.IncConsentRecorded("privacy", "federated_"+string(p))
	s.Metrics.ObserveFederatedDuration(time.Since(start).Seconds())
	return &CallbackOutput{Status: "pending_verification", Provider: string(p)}, nil
}

func (s *RegisterFederatedService) login(ctx context.Context, p user.Provider, u *user.User, result string, in CallbackInput, start time.Time, subHash, emailHash string) (*CallbackOutput, error) {
	switch u.Status {
	case user.StatusActive:
		sess, _ := s.issueSession(ctx, u.ID, in)
		s.putIdem(ctx, in.RequestID, "active")
		_ = s.Audit.Log(ctx, "federated.login", map[string]string{
			"action": "federated.login", "provider": string(p),
			"sub_hash": subHash, "email_hash": emailHash, "result": result,
		})
		s.Metrics.IncFederated(string(p), result)
		return &CallbackOutput{Status: "active", Provider: string(p), Session: sess}, nil
	case user.StatusPendingVerification:
		s.putIdem(ctx, in.RequestID, "pending_verification")
		_ = s.Audit.Log(ctx, "federated.login", map[string]string{
			"action": "federated.login", "provider": string(p),
			"sub_hash": subHash, "email_hash": emailHash, "result": "pending",
		})
		s.Metrics.IncFederated(string(p), "pending")
		return &CallbackOutput{Status: "pending_verification", Provider: string(p)}, nil
	default:
		s.Metrics.IncFederated(string(p), "error")
		return nil, fmt.Errorf("account status %s: %w", u.Status, auth.ErrAccountUnavailable)
	}
}

// collision: anti-takeover — sin crear ni fusionar, notify throttled al dueño.
func (s *RegisterFederatedService) collision(ctx context.Context, p user.Provider, existingID, normalized, emailHash, subHash, sub string, in CallbackInput) {
	notifyAllowed := true
	if s.Throttle != nil {
		if ok, terr := s.Throttle.AllowOwnerNotify(ctx, emailHash); terr == nil {
			notifyAllowed = ok
		}
	}
	if user.ShouldNotify(true, notifyAllowed) && s.Outbox != nil {
		payload, _ := json.Marshal(map[string]any{
			"email_hash": "sha256:" + emailHash, "provider": string(p),
			"sub_hash": "sha256:" + subHash, "existing_user_id": existingID,
			"ip_hash": "sha256:" + sha256HexShort(in.IP), "action": "notify_owner_require_link",
		})
		_ = s.Outbox.Enqueue(ctx, []user.OutboxPayload{{
			EventID: newUUIDv7(), EventType: "security.federated_collision",
			AggregateID: existingID, Topic: "auth.security.federated_collision.v1",
			PayloadJSON: payload,
		}})
	}
	_ = s.Audit.Log(ctx, "federated.collision", map[string]string{
		"action": "federated.collision", "provider": string(p),
		"sub_hash": subHash, "email_hash": emailHash, "result": "link_required",
	})
}

func (s *RegisterFederatedService) creationEvents(p user.Provider, u *user.User, fed *user.FederatedIdentity, emailHash, normalized string, verified bool, requestID string, now time.Time) ([]user.OutboxPayload, user.MailPayload) {
	subHash := sha256HexShort(fed.Sub)
	regPayload, _ := json.Marshal(map[string]any{
		"user_id": u.ID, "provider": string(p), "sub_hash": "sha256:" + subHash,
		"email_hash": "sha256:" + emailHash, "email_domain": user.DomainOf(normalized),
		"email_verified_by_idp": verified, "status": map[bool]string{true: "active", false: "pending_verification"}[verified],
		"request_id": requestID,
	})
	status := "pending_verification"
	if verified {
		status = "active"
	}
	events := []user.OutboxPayload{{
		EventID: newUUIDv7(), EventType: "federated.registered",
		AggregateID: u.ID, Topic: "auth.federated.registered.v1", PayloadJSON: regPayload,
	}}
	var mail user.MailPayload
	if verified {
		actPayload, _ := json.Marshal(map[string]any{
			"user_id": u.ID, "activated_at": now.Format("2006-01-02T15:04:05Z"), "method": "federated",
		})
		events = append(events, user.OutboxPayload{
			EventID: newUUIDv7(), EventType: "user.activated",
			AggregateID: u.ID, Topic: "auth.user.activated.v1", PayloadJSON: actPayload,
		})
		mail = user.MailPayload{
			To: normalized, Subject: "Bienvenido",
			Body: "Creaste tu cuenta con Google. Ya puedes iniciar sesion.\n",
		}
	}
	auditPayload, _ := json.Marshal(map[string]any{
		"action": "federated.register", "provider": string(p),
		"sub_hash": "sha256:" + subHash, "email_hash": "sha256:" + emailHash,
		"result": status,
	})
	events = append(events, user.OutboxPayload{
		EventID: newUUIDv7(), EventType: "audit.federated",
		AggregateID: u.ID, Topic: "auth.audit.v1", PayloadJSON: auditPayload,
	})
	return events, mail
}

func (s *RegisterFederatedService) issueSession(ctx context.Context, userID string, in CallbackInput) (*SessionData, error) {
	if s.Sessions == nil {
		return nil, nil
	}
	ua := in.UserAgent
	if ua == "" {
		ua = "federated-web"
	}
	ip := in.IP
	if ip == "" {
		ip = "unknown"
	}
	pair, err := s.Sessions.Issue(ctx, auth.SessionRequest{
		UserID: userID, Method: auth.MethodFederatedGoogle,
		AMR: []auth.AMR{auth.AMRFederatedGoogle}, AuthTime: time.Now().UTC(),
		Device: auth.Device{IPHash: sha256HexShort(ip + "/24"), UAHash: sha256HexShort(ua)},
		Roles: []string{"user"},
	})
	if err != nil {
		return nil, err
	}
	return &SessionData{AccessToken: pair.AccessJWT, RefreshTokenID: pair.RefreshPlain, ExpiresAt: pair.ExpiresAt.Unix(), SID: pair.SID}, nil
}

func (s *RegisterFederatedService) putIdem(ctx context.Context, requestID, status string) {
	if s.Idem == nil || requestID == "" {
		return
	}
	_ = s.Idem.Put(ctx, requestID, status, 24*time.Hour)
}

func sha256HexShort(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
