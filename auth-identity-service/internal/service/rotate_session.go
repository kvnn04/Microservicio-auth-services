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

	"github.com/google/uuid"
)

// NoopRotationMetrics default sin telemetría (tests).
type NoopRotationMetrics struct{}

func (NoopRotationMetrics) IncRotation(string)            {}
func (NoopRotationMetrics) ObserveRotationDuration(float64) {}
func (NoopRotationMetrics) IncReuseDetected()              {}
func (NoopRotationMetrics) IncConcurrent()                 {}

var _ auth.RotationMetrics = NoopRotationMetrics{}

// RotateInput renovación por Refresh (sin Bearer: el Refresh manda).
// RequestID alimenta la gracia idempotente 60s (mismo par al replay).
type RotateInput struct {
	RefreshPlain string
	RequestID    string
	IP           string
	UserAgent    string
}

// RotateOutput 200 (rotate o grace-idempotente: mismo shape, mismo par).
type RotateOutput struct {
	Status       string // siempre "rotated"
	AccessToken  string
	RefreshToken string
	ExpiresIn    int // TTL del Access (900s)
	// RefreshExpiresAt expiración del sliding del NUEVO Refresh (cookie).
	RefreshExpiresAt time.Time
	SID              string
}

// RotateService orquesta POST /refresh (CU-SES-04). Solo puertos.
// Sin Bearer/Step-Up/locks. Single-use estricto + CAS + gracia RequestID +
// 409 con algoritmo cliente + global ante reuso (delega SES-02).
type RotateService struct {
	Store   auth.RotationStore
	Signer  auth.AccessSigner
	Refresh auth.RefreshGenerator
	Limiter auth.LogoutLimiter
	Idem    shared.IdempotencyStore
	Audit   shared.AuditLogger
	Metrics auth.RotationMetrics
	Tracer  TracerPort
	Now     func() time.Time
}

func NewRotateService(
	store auth.RotationStore,
	signer auth.AccessSigner,
	refresh auth.RefreshGenerator,
	limiter auth.LogoutLimiter,
	idem shared.IdempotencyStore,
	audit shared.AuditLogger,
	metrics auth.RotationMetrics,
	tracer TracerPort,
) *RotateService {
	if metrics == nil {
		metrics = NoopRotationMetrics{}
	}
	if tracer == nil {
		tracer = NoopTracer{}
	}
	if audit == nil {
		audit = NoopAudit{}
	}
	return &RotateService{
		Store: store, Signer: signer, Refresh: refresh, Limiter: limiter,
		Idem: idem, Audit: audit, Metrics: metrics, Tracer: tracer,
		Now: time.Now,
	}
}

func (s *RotateService) nowUTC() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// Execute implementa §3: forma→rate→idempotencia→lookup→decide→
// rotate|grace|concurrent|global→200/409/401.
func (s *RotateService) Execute(ctx context.Context, in RotateInput) (*RotateOutput, error) {
	start := time.Now()
	ctx, span := s.Tracer.Start(ctx, "UseCase.RotateSession")
	defer span.End()
	now := s.nowUTC()

	plain := strings.TrimSpace(in.RefreshPlain)
	if !isValidRefreshPlain(plain) {
		s.doneRotation("invalid", start)
		return nil, &ValidationError{Fields: []FieldError{{Field: "refresh_token", Reason: "INVALID_FORMAT"}}}
	}
	hash := rotateRefreshHash(plain)

	// Rate anti-ruido (sin rotar ni quemar): IP 30/min + hash 10/min.
	_, rateSpan := s.Tracer.Start(ctx, "ratelimit")
	rerr := s.checkRate(ctx, hash, in.IP)
	rateSpan.End()
	if rerr != nil {
		s.doneRotation("rate_limited", start)
		return nil, rerr
	}

	// Gracia idempotente: mismo RequestID (60s) → mismo par, sin tocar chain.
	requestID := strings.TrimSpace(in.RequestID)
	useIdem := false
	if _, err := uuid.Parse(requestID); err == nil && requestID != "" && s.Idem != nil {
		useIdem = true
		if v, found, _ := s.Idem.Get(ctx, refreshIdemKey(requestID)); found {
			if pair, ok := parseRotatedPair(v); ok {
				s.Metrics.IncRotation("grace_idempotent")
				s.Metrics.ObserveRotationDuration(time.Since(start).Seconds())
				return &RotateOutput{Status: "rotated", AccessToken: pair.AccessJWT,
					RefreshToken: pair.Refresh, ExpiresIn: 900,
					RefreshExpiresAt: pair.ExpiresAt, SID: pair.SID}, nil
			}
		}
	}

	// Lookup (lectura; la Tx con FOR UPDATE vive dentro de RotateCAS).
	_, lookupSpan := s.Tracer.Start(ctx, "db.refresh.lookup")
	lkp, lerr := s.Store.Lookup(ctx, hash)
	lookupSpan.End()
	if lerr != nil {
		if errors.Is(lerr, auth.ErrRefreshNotFound) {
			s.auditRotate(ctx, "", "", hash, "invalid")
			s.doneRotation("invalid", start)
			return nil, auth.ErrRefreshNotFound
		}
		s.doneRotation("error", start)
		return nil, fmt.Errorf("lookup: %w", auth.ErrSessionInfra)
	}
	st := lkp.State

	// Familia muerta por logout → 401 (front re-loguea, sin alarma robo).
	if st.Revoked {
		s.auditRotate(ctx, st.UserID, st.Family, hash, "revoked")
		s.doneRotation("revoked", start)
		return nil, auth.ErrRefreshRevoked
	}
	// Absolute/sliding pasado → 401 (marca revoked best-effort, sin alarma).
	if !now.Before(st.AbsoluteExp) || !now.Before(lkp.SlidingExp) {
		_ = s.Store.ExpireFamily(ctx, st.Family)
		s.auditRotate(ctx, st.UserID, st.Family, hash, "expired")
		s.doneRotation("expired", start)
		return nil, auth.ErrRefreshExpired
	}

	// Decisión pura: current / parent+gracia+device+flaps / reuso.
	// Los flaps se cuentan al decidir concurrent (IncrFlaps) para no
	// quemar contador en caminos directos a reuso.
	sameDevice := auth.DeviceMatch(st.DeviceHash, in.IP, in.UserAgent)
	withinGrace := !st.RotatedAt.IsZero() && now.Sub(st.RotatedAt) <= auth.GraceWindow
	presentedFP := rotateDeviceFP(in.IP, in.UserAgent)
	switch auth.DecideRotate(lkp.IsCurrent, lkp.IsParent, withinGrace, sameDevice, 0) {
	case auth.DecideRotateCurrent:
		return s.doRotate(ctx, in, lkp, hash, presentedFP, requestID, useIdem, start, now)
	case auth.DecideConcurrent:
		return s.resolveConcurrent(ctx, in, lkp, hash, start, now)
	default:
		return s.doReuse(ctx, in, lkp, hash, presentedFP, start, now)
	}
}

// doRotate genera el par hijo y lo persiste con CAS.
func (s *RotateService) doRotate(ctx context.Context, in RotateInput, lkp auth.RotationLookup, hash, presentedFP, requestID string, useIdem bool, start, now time.Time) (*RotateOutput, error) {
	st := lkp.State
	newPlain, newHash, gerr := s.Refresh.Generate(ctx)
	if gerr != nil || newPlain == "" {
		s.doneRotation("error", start)
		return nil, fmt.Errorf("refresh: %w", auth.ErrSessionInfra)
	}
	newJTI := newUUIDv7()
	claims, cerr := s.buildRotateClaims(st, newJTI, now)
	if cerr != nil {
		s.doneRotation("error", start)
		return nil, cerr
	}
	_, signSpan := s.Tracer.Start(ctx, "crypto.ed25519.sign")
	jwt, _, serr := s.Signer.Sign(ctx, claims)
	signSpan.End()
	if serr != nil {
		s.doneRotation("error", start)
		return nil, fmt.Errorf("sign: %w", auth.ErrSessionInfra)
	}
	slidingTo := now.Add(auth.RefreshSlidingTTL)
	if st.AbsoluteExp.Before(slidingTo) {
		slidingTo = st.AbsoluteExp // acotado al absoluto (RN-02)
	}
	_, casSpan := s.Tracer.Start(ctx, "db.rotate")
	pair, cerr := s.Store.RotateCAS(ctx, auth.RotateCASInput{
		State: st, OldHash: hash,
		NewPair: auth.RotatedPair{AccessJWT: jwt, Refresh: newPlain,
			ExpiresAt: slidingTo, SID: st.SID, Family: st.Family, JTI: newJTI,
			Counter: st.Counter + 1},
		NewHash: newHash, SlidingTo: slidingTo, PresentedFP: presentedFP,
	})
	casSpan.End()
	if cerr != nil {
		if errors.Is(cerr, auth.ErrRefreshConcurrent) {
			return s.resolveConcurrent(ctx, in, lkp, hash, start, now)
		}
		if errors.Is(cerr, auth.ErrRefreshRevoked) {
			s.auditRotate(ctx, st.UserID, st.Family, hash, "revoked")
			s.doneRotation("revoked", start)
			return nil, auth.ErrRefreshRevoked
		}
		s.doneRotation("error", start)
		return nil, fmt.Errorf("rotate: %w", auth.ErrSessionInfra)
	}
	if useIdem {
		_ = s.Idem.Put(ctx, refreshIdemKey(requestID), marshalRotatedPair(pair), auth.IdempotencyWindow)
	}
	s.Metrics.IncRotation("ok")
	s.Metrics.ObserveRotationDuration(time.Since(start).Seconds())
	return &RotateOutput{Status: "rotated", AccessToken: pair.AccessJWT,
		RefreshToken: pair.Refresh, ExpiresIn: 900,
		RefreshExpiresAt: pair.ExpiresAt, SID: pair.SID}, nil
}

// buildRotateClaims re-firma preservando auth_time/amr/roles (RN-04:
// no rejuvenece Step-Up; CU-SEC-06 fuerza re-login ante cambio de roles).
func (s *RotateService) buildRotateClaims(st auth.FamilyState, newJTI string, now time.Time) (auth.AccessClaims, error) {
	amr := make([]auth.AMR, 0, len(st.AMR))
	for _, a := range st.AMR {
		switch auth.AMR(a) {
		case auth.AMRPassword, auth.AMRTOTP, auth.AMRBackup, auth.AMRFederatedGoogle, auth.AMROTPEmail:
			amr = append(amr, auth.AMR(a))
		}
	}
	if len(amr) == 0 {
		return auth.AccessClaims{}, fmt.Errorf("amr vacío: %w", auth.ErrSessionInfra)
	}
	roles := st.Roles
	if len(roles) == 0 {
		roles = []string{"user"}
	}
	authTime := st.AuthTime
	if authTime.IsZero() {
		authTime = now
	}
	return auth.NewAccessClaims("", "", st.UserID, st.SID, newJTI, authTime, amr, roles, st.RolesVer, now)
}

// resolveConcurrent cuenta el flap: <4 en 10s → 409 reintentable;
// 4º con el mismo viejo → global (anti-flapping ladrón).
func (s *RotateService) resolveConcurrent(ctx context.Context, in RotateInput, lkp auth.RotationLookup, hash string, start, now time.Time) (*RotateOutput, error) {
	flaps, ferr := s.Store.IncrFlaps(ctx, hash)
	if ferr != nil {
		flaps = 0 // fail-open a 409 (sin escalar) si Redis cae
	}
	if flaps > int64(auth.ConcurrentLimit) {
		return s.doReuse(ctx, in, lkp, hash, rotateDeviceFP(in.IP, in.UserAgent), start, now)
	}
	s.Metrics.IncRotation("concurrent")
	s.Metrics.IncConcurrent()
	s.Metrics.ObserveRotationDuration(time.Since(start).Seconds())
	return nil, auth.ErrRefreshConcurrent
}

// doReuse ejecuta el corte GLOBAL + evidencia P1 (robo).
func (s *RotateService) doReuse(ctx context.Context, in RotateInput, lkp auth.RotationLookup, hash, presentedFP string, start, now time.Time) (*RotateOutput, error) {
	st := lkp.State
	_, globalSpan := s.Tracer.Start(ctx, "global_revoke")
	_, gerr := s.Store.ReuseGlobal(ctx, auth.ReuseGlobalInput{
		State: st, PresentedHash: hash, PresentedDevice: presentedFP,
		PresentedAt: now, IP: in.IP, CounterPresented: lkp.CounterPresented,
	})
	globalSpan.End()
	if gerr != nil {
		s.doneRotation("error", start)
		return nil, fmt.Errorf("reuse global: %w", auth.ErrSessionInfra)
	}
	s.Metrics.IncRotation("reuse")
	s.Metrics.IncReuseDetected()
	s.Metrics.ObserveRotationDuration(time.Since(start).Seconds())
	return nil, auth.ErrRefreshCompromised
}

func (s *RotateService) checkRate(ctx context.Context, hash, ip string) error {
	if s.Limiter == nil {
		return nil
	}
	if ip != "" {
		ok, _, lerr := s.Limiter.Allow(ctx, "refresh:ip:"+ip, auth.RefreshRateIP, auth.RefreshRateWindow)
		if lerr == nil && !ok {
			return auth.ErrRateLimited
		}
	}
	ok, _, lerr := s.Limiter.Allow(ctx, "refresh:fam:"+hash, auth.RefreshRateFam, auth.RefreshRateWindow)
	if lerr == nil && !ok {
		return auth.ErrRateLimited
	}
	return nil
}

func (s *RotateService) auditRotate(ctx context.Context, userID, family, hash, result string) {
	if s.Audit == nil {
		return
	}
	_ = s.Audit.Log(ctx, "session.rotate", map[string]string{
		"action": "session.rotate", "user_id": userID, "family": family,
		"hash_prefix": auth.HashPrefix8(hash), "result": result,
	})
}

func (s *RotateService) doneRotation(result string, start time.Time) {
	s.Metrics.IncRotation(result)
	s.Metrics.ObserveRotationDuration(time.Since(start).Seconds())
}

// rotateRefreshHash SHA-256 hex del plano (igual generator).
func rotateRefreshHash(plain string) string {
	h := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(h[:])
}

// rotateDeviceFP huella presentada (mismo esquema que el Issue guarda;
// DeviceMatch la compara contra S1/S2 históricos).
func rotateDeviceFP(ip, ua string) string {
	ih := sha256.Sum256([]byte(ip + "/24"))
	uh := sha256.Sum256([]byte(ua))
	sum := sha256.Sum256([]byte(hex.EncodeToString(ih[:]) + hex.EncodeToString(uh[:])))
	return hex.EncodeToString(sum[:])
}

func refreshIdemKey(reqID string) string { return "refresh:" + reqID }

func marshalRotatedPair(p auth.RotatedPair) string {
	b, _ := json.Marshal(map[string]any{
		"access": p.AccessJWT, "refresh": p.Refresh,
		"exp": p.ExpiresAt.Unix(), "sid": p.SID,
	})
	return string(b)
}

func parseRotatedPair(v string) (auth.RotatedPair, bool) {
	var m struct {
		Access  string `json:"access"`
		Refresh string `json:"refresh"`
		Exp     int64  `json:"exp"`
		SID     string `json:"sid"`
	}
	if err := json.Unmarshal([]byte(v), &m); err != nil {
		return auth.RotatedPair{}, false
	}
	if m.Access == "" || m.Refresh == "" || m.SID == "" || m.Exp <= 0 {
		return auth.RotatedPair{}, false
	}
	return auth.RotatedPair{AccessJWT: m.Access, Refresh: m.Refresh,
		ExpiresAt: time.Unix(m.Exp, 0).UTC(), SID: m.SID}, true
}
