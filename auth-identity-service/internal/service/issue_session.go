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

// NoopIssueMetrics default sin telemetría (tests).
type NoopIssueMetrics struct{}

func (NoopIssueMetrics) IncIssued(string, string)     {}
func (NoopIssueMetrics) ObserveIssueDuration(float64) {}
func (NoopIssueMetrics) IncEvicted(string)            {}
func (NoopIssueMetrics) IncRedisFallback()            {}
func (NoopIssueMetrics) IncInfraError(string)         {}

var _ auth.SessionIssueMetrics = NoopIssueMetrics{}

// IssueService implementa auth.SessionIssuer (CU-AUTH-04).
// Único punto que firma Access y crea families; login/MFA/federado lo invocan.
// Orden vinculante: firma → Tx(PG) → Redis → entrega. Si Tx falla se descarta
// el JWT (sin huérfanos). Redis down → entrega igual vía PG + fallback metric.
type IssueService struct {
	Signer  auth.AccessSigner
	Refresh auth.RefreshGenerator
	Store   auth.SessionStore
	Cache   auth.SessionCache // opcional (nil = sin Redis)
	Users   user.UserRepository
	Outbox  OutboxEnqueuer // reservado (el Store persiste outbox en Tx)
	Audit   shared.AuditLogger
	Metrics auth.SessionIssueMetrics
	Tracer  TracerPort
	Issuer  string
	Audience string
	Now     func() time.Time
}

func NewIssueService(
	signer auth.AccessSigner,
	refresh auth.RefreshGenerator,
	store auth.SessionStore,
	cache auth.SessionCache,
	users user.UserRepository,
	audit shared.AuditLogger,
	metrics auth.SessionIssueMetrics,
	tracer TracerPort,
	issuer, audience string,
) *IssueService {
	if metrics == nil {
		metrics = NoopIssueMetrics{}
	}
	if tracer == nil {
		tracer = NoopTracer{}
	}
	if audit == nil {
		audit = NoopAudit{}
	}
	if issuer == "" {
		issuer = auth.DefaultIssuer
	}
	if audience == "" {
		audience = auth.DefaultAudience
	}
	return &IssueService{
		Signer: signer, Refresh: refresh, Store: store, Cache: cache,
		Users: users, Audit: audit, Metrics: metrics, Tracer: tracer,
		Issuer: issuer, Audience: audience, Now: time.Now,
	}
}

// Issue emite el par de sesión (firma Ed25519 15min + Refresh opaco 32B).
func (s *IssueService) Issue(ctx context.Context, req auth.SessionRequest) (auth.IssuedPair, error) {
	return s.issue(ctx, req)
}

func (s *IssueService) issue(ctx context.Context, req auth.SessionRequest) (auth.IssuedPair, error) {
	start := time.Now()
	now := s.Now().UTC()
	if s.Now == nil {
		now = time.Now().UTC()
	}
	ctx, span := s.Tracer.Start(ctx, "Session.Issue")
	defer span.End()

	// 1. Validación de forma (pura, sin I/O).
	if err := req.ValidateRequest(now); err != nil {
		return auth.IssuedPair{}, err
	}
	// 1b. ACTIVE (defensa en profundidad; si Users==nil confía en llamador).
	if s.Users != nil {
		u, ferr := s.Users.FindByID(ctx, req.UserID)
		if ferr != nil {
			return auth.IssuedPair{}, fmt.Errorf("find user: %w", auth.ErrSessionInfra)
		}
		if u.Status != user.StatusActive {
			return auth.IssuedPair{}, auth.ErrInvalidSessionRequest
		}
	}
	if s.Signer == nil || s.Refresh == nil || s.Store == nil {
		s.Metrics.IncInfraError("misconfigured")
		return auth.IssuedPair{}, fmt.Errorf("misconfigured: %w", auth.ErrSessionInfra)
	}
	roles := req.Roles
	if roles == nil {
		roles = []string{"user"}
	}

	// 2 intentos máx ante colisión CSPRNG/UUID (prob ~0, UNIQUE PG la rechaza).
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		pair, err := s.tryOnce(ctx, req, roles, now, start)
		if err == nil {
			return pair, nil
		}
		if errors.Is(err, auth.ErrSessionConflict) && attempt == 0 {
			lastErr = err
			continue
		}
		return auth.IssuedPair{}, err
	}
	s.Metrics.IncInfraError("conflict")
	return auth.IssuedPair{}, fmt.Errorf("retry: %w", lastErr)
}

func (s *IssueService) tryOnce(ctx context.Context, req auth.SessionRequest, roles []string, now time.Time, start time.Time) (auth.IssuedPair, error) {
	sid, err := newUUIDv7Str()
	if err != nil {
		return auth.IssuedPair{}, fmt.Errorf("sid: %w", auth.ErrSessionInfra)
	}
	jti, err := newUUIDv7Str()
	if err != nil {
		return auth.IssuedPair{}, fmt.Errorf("jti: %w", auth.ErrSessionInfra)
	}
	family, err := newUUIDv7Str()
	if err != nil {
		return auth.IssuedPair{}, fmt.Errorf("family: %w", auth.ErrSessionInfra)
	}
	// Refresh opaco.
	_, refreshSpan := s.Tracer.Start(ctx, "crypto.refresh.generate")
	plain, hash, gerr := s.Refresh.Generate(ctx)
	refreshSpan.End()
	if gerr != nil {
		s.Metrics.IncInfraError("refresh")
		return auth.IssuedPair{}, fmt.Errorf("refresh: %w", auth.ErrSessionInfra)
	}
	if len(plain) == 0 || len(hash) == 0 {
		s.Metrics.IncInfraError("refresh")
		return auth.IssuedPair{}, fmt.Errorf("refresh empty: %w", auth.ErrSessionInfra)
	}
	// Claims + firma (en memoria; si Tx falla se descarta, sin huérfanos).
	claims, cerr := auth.NewAccessClaims(s.Issuer, s.Audience, req.UserID, sid, jti, req.AuthTime, req.AMR, roles, req.RolesVer, now)
	if cerr != nil {
		return auth.IssuedPair{}, cerr
	}
	_, signSpan := s.Tracer.Start(ctx, "crypto.ed25519.sign")
	jwt, kid, serr := s.Signer.Sign(ctx, claims)
	signSpan.End()
	if serr != nil {
		s.Metrics.IncInfraError("sign")
		if errors.Is(serr, auth.ErrNoKey) {
			return auth.IssuedPair{}, serr
		}
		return auth.IssuedPair{}, fmt.Errorf("sign: %w", auth.ErrSessionInfra)
	}
	deviceHash := issueSHA256(req.Device.IPHash + req.Device.UAHash)
	sess := auth.Session{
		SID: sid, UserID: req.UserID, Family: family, JTI: jti,
		DeviceHash: deviceHash, IPHash: req.Device.IPHash,
		CreatedAt: now, LastSeen: now, ExpiresAt: now.Add(auth.RefreshAbsoluteTTL),
	}
	fam := auth.RefreshFamily{
		Family: family, UserID: req.UserID, CurrentHash: hash,
		ParentHash: "", Counter: 0, AbsoluteExp: now.Add(auth.RefreshAbsoluteTTL),
	}
	rh := auth.RefreshHash{
		Hash: hash, Family: family, Counter: 0,
		ExpiresAt: now.Add(auth.RefreshSlidingTTL),
	}
	evt := buildIssuedEvent(req, sid, family, jti, kid, deviceHash, now)
	var evictEvt *user.OutboxPayload
	// El Store decide LRU internamente; aquí solo preparamos base.
	// Si el Store evicta, él genera session.evicted (lo recibe de vuelta vía SID).
	_, dbSpan := s.Tracer.Start(ctx, "db.session.insert")
	evictedSID, cerr := s.Store.Create(ctx, sess, fam, rh, evt, evictEvt)
	dbSpan.End()
	if cerr != nil {
		s.Metrics.IncInfraError("db")
		if errors.Is(cerr, auth.ErrSessionConflict) {
			return auth.IssuedPair{}, cerr
		}
		return auth.IssuedPair{}, fmt.Errorf("persist: %w", auth.ErrSessionInfra)
	}
	// Redis write-through (best-effort).
	if s.Cache != nil {
		_, cacheSpan := s.Tracer.Start(ctx, "cache.session.save")
		cerr := s.Cache.Save(ctx, sess, fam, jti)
		cacheSpan.End()
		if cerr != nil {
			s.Metrics.IncRedisFallback()
		}
	}
	if evictedSID != "" {
		s.Metrics.IncEvicted("lru")
	}
	// Métrica + auditoría (sin tokens, solo IDs).
	amrLabel := amrLabel(req.AMR)
	s.Metrics.IncIssued(req.Method, amrLabel)
	s.Metrics.ObserveIssueDuration(time.Since(start).Seconds())
	_ = s.Audit.Log(ctx, "session.issue", map[string]string{
		"action": "session.issue", "user_id": req.UserID,
		"sid": sid, "family": family, "jti": jti, "kid": kid,
		"method": req.Method, "amr": amrLabel, "device_hash": deviceHash,
	})
	return auth.IssuedPair{
		AccessJWT: jwt, RefreshPlain: plain,
		SID: sid, JTI: jti, Family: family, KID: kid,
		ExpiresAt: now.Add(auth.AccessTTL),
	}, nil
}

func buildIssuedEvent(req auth.SessionRequest, sid, family, jti, kid, deviceHash string, now time.Time) user.OutboxPayload {
	amr := make([]string, 0, len(req.AMR))
	for _, a := range req.AMR {
		amr = append(amr, string(a))
	}
	payload, _ := json.Marshal(map[string]any{
		"event_id": uuid.NewString(), "event_type": "session.issued",
		"occurred_at": now.Format("2006-01-02T15:04:05Z"),
		"payload": map[string]any{
			"user_id": req.UserID, "sid": sid, "family": family, "jti": jti,
			"kid": kid, "method": req.Method, "amr": amr,
			"device_hash": "sha256:" + deviceHash,
			"expires_at": now.Add(auth.RefreshSlidingTTL).Format("2006-01-02T15:04:05Z"),
		},
	})
	// El Store re-envelopa a columnas outbox; aquí devolvemos payload listo.
	// Hacemos doble-marshal compatible con UserRepository.Enqueue (PayloadJSON).
	inner, _ := json.Marshal(map[string]any{
		"user_id": req.UserID, "sid": sid, "family": family, "jti": jti,
		"kid": kid, "method": req.Method, "amr": amr,
		"device_hash": "sha256:" + deviceHash,
		"expires_at": now.Add(auth.RefreshSlidingTTL).Format("2006-01-02T15:04:05Z"),
	})
	_ = payload
	return user.OutboxPayload{
		EventID: uuid.NewString(), EventType: "session.issued",
		AggregateID: req.UserID, Topic: "auth.session.issued.v1", PayloadJSON: inner,
	}
}

func amrLabel(amr []auth.AMR) string {
	parts := make([]string, 0, len(amr))
	for _, a := range amr {
		parts = append(parts, string(a))
	}
	return strings.Join(parts, "+")
}

func issueSHA256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func newUUIDv7Str() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}
