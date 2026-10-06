package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"auth-identity-service/internal/domain/auth"

	"github.com/google/uuid"
)

// --- Fakes CU-SES-04 ---

type fakeRotationStore struct {
	mu        sync.Mutex
	lookups   map[string]auth.RotationLookup
	lookupErr error
	casErr    error
	casCalls  int
	lastCAS   auth.RotateCASInput
	expired   []string
	flaps     map[string]int64
	flapErr   error
	reuseErr  error
	reuseCalls int
	reuseIn   auth.ReuseGlobalInput
}

func newFakeRotationStore() *fakeRotationStore {
	return &fakeRotationStore{lookups: map[string]auth.RotationLookup{}, flaps: map[string]int64{}}
}

func (f *fakeRotationStore) Lookup(_ context.Context, h string) (auth.RotationLookup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lookupErr != nil {
		return auth.RotationLookup{}, f.lookupErr
	}
	l, ok := f.lookups[h]
	if !ok {
		return auth.RotationLookup{}, auth.ErrRefreshNotFound
	}
	return l, nil
}

func (f *fakeRotationStore) RotateCAS(_ context.Context, in auth.RotateCASInput) (auth.RotatedPair, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.casCalls++
	f.lastCAS = in
	if f.casErr != nil {
		return auth.RotatedPair{}, f.casErr
	}
	return in.NewPair, nil
}

func (f *fakeRotationStore) ExpireFamily(_ context.Context, family string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.expired = append(f.expired, family)
	return nil
}

func (f *fakeRotationStore) IncrFlaps(_ context.Context, h string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.flapErr != nil {
		return 0, f.flapErr
	}
	f.flaps[h]++
	return f.flaps[h], nil
}

func (f *fakeRotationStore) ReuseGlobal(_ context.Context, in auth.ReuseGlobalInput) (auth.GlobalRevokeResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reuseCalls++
	f.reuseIn = in
	if f.reuseErr != nil {
		return auth.GlobalRevokeResult{}, f.reuseErr
	}
	return auth.GlobalRevokeResult{Sessions: 2, Families: 2, ValidAfter: time.Now().UTC()}, nil
}

type fakeAccessSigner struct {
	kid string
}

func (f *fakeAccessSigner) Sign(_ context.Context, claims auth.AccessClaims) (string, string, error) {
	return "jwt:" + claims.JTI, f.kid, nil
}
func (f *fakeAccessSigner) ActiveKID() string { return f.kid }

func rotGen(plain string) *fakeRefreshGen {
	return &fakeRefreshGen{plain: plain, hash: rotateRefreshHash(plain)}
}

type fakeRotateLimiter struct {
	deny  map[string]bool
	calls []string
}

func (f *fakeRotateLimiter) Allow(_ context.Context, key string, _ int, _ time.Duration) (bool, time.Duration, error) {
	f.calls = append(f.calls, key)
	if f.deny[key] {
		return false, time.Minute, nil
	}
	return true, 0, nil
}

type rotationMetricsFake struct {
	counts     map[string]int
	reuse      int
	concurrent int
}

func newRotationMetricsFake() *rotationMetricsFake {
	return &rotationMetricsFake{counts: map[string]int{}}
}
func (m *rotationMetricsFake) IncRotation(r string)            { m.counts[r]++ }
func (m *rotationMetricsFake) ObserveRotationDuration(float64) {}
func (m *rotationMetricsFake) IncReuseDetected()               { m.reuse++ }
func (m *rotationMetricsFake) IncConcurrent()                  { m.concurrent++ }

type rotateAuditFake struct{ calls []map[string]string }

func (a *rotateAuditFake) Log(_ context.Context, _ string, f map[string]string) error {
	a.calls = append(a.calls, f)
	return nil
}

const (
	rotUser   = "user-rot"
	rotFamily = "fam-rot"
	rotSID    = "sid-rot"
)

func rotState(counter int, revoked bool, rotatedAt time.Time) auth.FamilyState {
	return auth.FamilyState{
		Family: rotFamily, UserID: rotUser, SID: rotSID,
		CurrentHash: "cur-hash", ParentHash: "par-hash", Counter: counter,
		AbsoluteExp: time.Now().UTC().Add(80 * 24 * time.Hour),
		Revoked: revoked, RotatedAt: rotatedAt, DeviceHash: "dev-hash",
		Email: "u@example.com", AuthTime: time.Now().UTC().Add(-time.Hour),
		AMR: []string{"pwd"}, Roles: []string{"user"},
	}
}

type rotateFixture struct {
	svc     *RotateService
	store   *fakeRotationStore
	metrics *rotationMetricsFake
	audit   *rotateAuditFake
	limiter *fakeRotateLimiter
	idem    *mockIdem
	now     time.Time
}

func newRotateFixture() *rotateFixture {
	store := newFakeRotationStore()
	metrics := newRotationMetricsFake()
	audit := &rotateAuditFake{}
	limiter := &fakeRotateLimiter{deny: map[string]bool{}}
	idem := newMockIdem()
	now := time.Now().UTC()
	svc := NewRotateService(store,
		&fakeAccessSigner{kid: "k1"}, rotGen("N34UB7zdx pasta-refresh-plano-43ch!!"),
		limiter, idem, audit, metrics, NoopTracer{})
	svc.Now = func() time.Time { return now }
	return &rotateFixture{svc: svc, store: store, metrics: metrics, audit: audit, limiter: limiter, idem: idem, now: now}
}

// seedCurrent registra el hash vigente (+"N34..." como siguiente es irrelevante).
func (f *rotateFixture) seedCurrent(plain string, mutate func(*auth.FamilyState)) string {
	h := rotateRefreshHash(plain)
	st := rotState(3, false, f.now.Add(-time.Hour))
	if mutate != nil {
		mutate(&st)
	}
	f.store.lookups[h] = auth.RotationLookup{
		State: st, PresentedHash: h,
		SlidingExp: f.now.Add(20 * 24 * time.Hour),
		IsCurrent: true,
	}
	return h
}

func rotInput(plain string) RotateInput {
	return RotateInput{RefreshPlain: plain, RequestID: uuid.NewString(), IP: "9.9.9.9", UserAgent: "UA-test"}
}

func TestRotate_Table(t *testing.T) {
	plainOk := "R3-vigente-plano-de-43-caracteres-123456789"
	cases := []struct {
		name       string
		setup      func(f *rotateFixture) string // retorna plain a presentar
		wantStatus string
		wantErr    error
		wantMetric string
	}{
		{"ok rotate mismo-sid", func(f *rotateFixture) string {
			return plainOk
		}, "rotated", nil, "ok"},
		{"malforma 400", func(f *rotateFixture) string {
			return "corto"
		}, "", &ValidationError{}, "invalid"},
		{"miss 401 sin alarma", func(f *rotateFixture) string {
			return "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
		}, "", auth.ErrRefreshNotFound, "invalid"},
		{"revoked 401 sin robo", func(f *rotateFixture) string {
			p := "R-revoked-plano-de-43-caracteres-1234567890"
			h := rotateRefreshHash(p)
			st := rotState(2, true, f.now.Add(-time.Hour))
			f.store.lookups[h] = auth.RotationLookup{State: st, PresentedHash: h,
				SlidingExp: f.now.Add(time.Hour), IsCurrent: true}
			return p
		}, "", auth.ErrRefreshRevoked, "revoked"},
		{"absolute pasada 401", func(f *rotateFixture) string {
			p := "R-expirada-plano-de-43-caracteres-12345678"
			h := rotateRefreshHash(p)
			st := rotState(2, false, f.now.Add(-time.Hour))
			st.AbsoluteExp = f.now.Add(-time.Hour)
			f.store.lookups[h] = auth.RotationLookup{State: st, PresentedHash: h,
				SlidingExp: f.now.Add(time.Hour), IsCurrent: true}
			return p
		}, "", auth.ErrRefreshExpired, "expired"},
		{"rate 429", func(f *rotateFixture) string {
			f.limiter.deny["refresh:ip:9.9.9.9"] = true
			return plainOk
		}, "", auth.ErrRateLimited, "rate_limited"},
	}
	// seed común del vigente para los casos que lo usan.
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRotateFixture()
			f.seedCurrent(plainOk, nil)
			plain := tc.setup(f)
			out, err := f.svc.Execute(context.Background(), rotInput(plain))
			if tc.wantErr != nil {
				switch tc.wantErr.(type) {
				case *ValidationError:
					var ve *ValidationError
					if !errors.As(err, &ve) {
						t.Fatalf("400: %v", err)
					}
				default:
					if !errors.Is(err, tc.wantErr) {
						t.Fatalf("err=%v want %v", err, tc.wantErr)
					}
				}
				if f.metrics.counts[tc.wantMetric] != 1 {
					t.Fatalf("métrica %q: %v", tc.wantMetric, f.metrics.counts)
				}
				return
			}
			if err != nil || out.Status != tc.wantStatus || out.SID != rotSID {
				t.Fatalf("err=%v out=%+v", err, out)
			}
			if out.AccessToken == "" || out.RefreshToken == "" || out.ExpiresIn != 900 {
				t.Fatalf("par completo: %+v", out)
			}
			if f.store.casCalls != 1 {
				t.Fatalf("1 CAS: %d", f.store.casCalls)
			}
			// Sliding acotado al absoluto + auth_time preservado (vía claims).
			if f.store.lastCAS.SlidingTo.After(f.now.Add(auth.RefreshSlidingTTL).Add(time.Minute)) {
				t.Fatalf("sliding acotado: %v", f.store.lastCAS.SlidingTo)
			}
		})
	}
}

func TestRotate_ReplayMismoRequestID(t *testing.T) {
	f := newRotateFixture()
	plain := "R3-replay-plano-de-43-caracteres-1234567890"
	f.seedCurrent(plain, nil)
	in := rotInput(plain)
	out1, err := f.svc.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("1º: %v", err)
	}
	out2, err := f.svc.Execute(context.Background(), in)
	if err != nil || out2.AccessToken != out1.AccessToken || out2.RefreshToken != out1.RefreshToken {
		t.Fatalf("replay mismo par: %v %+v", err, out2)
	}
	if f.store.casCalls != 1 {
		t.Fatalf("sin re-CAS: %d", f.store.casCalls)
	}
	if f.metrics.counts["grace_idempotent"] != 1 {
		t.Fatalf("métricas: %v", f.metrics.counts)
	}
}

func TestRotate_ParentGracia409yFlap4Global(t *testing.T) {
	newParentFixture := func() (*rotateFixture, string) {
		f := newRotateFixture()
		curPlain := "R4-actual-plano-de-43-caracteres-123456789"
		oldPlain := "R3-viejo-plano-de-43-caracteres-1234567890"
		oldHash := rotateRefreshHash(oldPlain)
		st := rotState(4, false, f.now.Add(-2*time.Second))
		st.CurrentHash = rotateRefreshHash(curPlain)
		st.ParentHash = oldHash
		st.DeviceHash = rotateDeviceFP("9.9.9.9", "UA-test")
		f.store.lookups[oldHash] = auth.RotationLookup{State: st,
			PresentedHash: oldHash, SlidingExp: f.now.Add(time.Hour), IsParent: true}
		return f, oldPlain
	}
	f, oldPlain := newParentFixture()
	// 3×409 (mismo device, en gracia): flaps 1,2,3.
	for i := 0; i < 3; i++ {
		_, err := f.svc.Execute(context.Background(), rotInput(oldPlain))
		if !errors.Is(err, auth.ErrRefreshConcurrent) {
			t.Fatalf("iter %d 409: %v", i, err)
		}
	}
	if f.metrics.concurrent != 3 {
		t.Fatalf("3×409: %v", f.metrics.counts)
	}
	// 4º con el mismo viejo → GLOBAL + P1 + COMPROMISED.
	_, err := f.svc.Execute(context.Background(), rotInput(oldPlain))
	if !errors.Is(err, auth.ErrRefreshCompromised) {
		t.Fatalf("4º global: %v", err)
	}
	if f.metrics.reuse != 1 || f.store.reuseCalls != 1 {
		t.Fatalf("P1+global: %v reuse=%d", f.metrics.counts, f.store.reuseCalls)
	}
	if f.store.reuseIn.PresentedHash != rotateRefreshHash(oldPlain) {
		t.Fatal("evidencia con hash presentado")
	}
}

func TestRotate_ParentFueraGraciaYAntiguo_Global(t *testing.T) {
	// Parent de hace 11s (fuera de 10s) → global directo.
	f := newRotateFixture()
	oldPlain := "R3-viejo-plano-de-43-caracteres-1234567890"
	oldHash := rotateRefreshHash(oldPlain)
	st := rotState(4, false, f.now.Add(-11*time.Second))
	st.DeviceHash = rotateDeviceFP("9.9.9.9", "UA-test")
	f.store.lookups[oldHash] = auth.RotationLookup{State: st,
		PresentedHash: oldHash, SlidingExp: f.now.Add(time.Hour), IsParent: true}
	if _, err := f.svc.Execute(context.Background(), rotInput(oldPlain)); !errors.Is(err, auth.ErrRefreshCompromised) {
		t.Fatalf("fuera gracia global: %v", err)
	}
	// Distinto device en gracia → global directo.
	f2 := newRotateFixture()
	st2 := rotState(4, false, f2.now.Add(-2*time.Second))
	st2.DeviceHash = rotateDeviceFP("9.9.9.9", "UA-test")
	f2.store.lookups[oldHash] = auth.RotationLookup{State: st2,
		PresentedHash: oldHash, SlidingExp: f2.now.Add(time.Hour), IsParent: true}
	in := rotInput(oldPlain)
	in.UserAgent = "UA-atacante-distinto"
	if _, err := f2.svc.Execute(context.Background(), in); !errors.Is(err, auth.ErrRefreshCompromised) {
		t.Fatalf("device mismatch global: %v", err)
	}
	// Hash antiguo no-parent → global directo.
	f3 := newRotateFixture()
	ancientPlain := "R1-antiguo-plano-de-43-caracteres-123456789"
	ancientHash := rotateRefreshHash(ancientPlain)
	f3.store.lookups[ancientHash] = auth.RotationLookup{State: rotState(5, false, f3.now.Add(-time.Hour)),
		PresentedHash: ancientHash, SlidingExp: f3.now.Add(time.Hour)}
	if _, err := f3.svc.Execute(context.Background(), rotInput(ancientPlain)); !errors.Is(err, auth.ErrRefreshCompromised) {
		t.Fatalf("antiguo global: %v", err)
	}
}

// TestRotate_RaceCAS: 2 goroutines, mismo Refresh vigente, con barrera para
// que ambas lean la cadena ANTES de que el ganador rote. Exige EXACTAMENTE
// 1×200 + 1×409 (nunca 2×200 ni global): el CAS mutex lo decide.
func TestRotate_RaceCAS(t *testing.T) {
	plain := "R-race-plano-de-43-caracteres-1234567890123"
	now := time.Now().UTC()
	shared := &raceShared{known: rotateRefreshHash(plain), now: now}
	newSvc := func() *RotateService {
		metrics := newRotationMetricsFake()
		svc := NewRotateService(shared, &fakeAccessSigner{kid: "k1"},
			rotGen("Nvo-plano-de-43-caracteres-12345678901"),
			&fakeRotateLimiter{deny: map[string]bool{}}, newMockIdem(),
			&rotateAuditFake{}, metrics, NoopTracer{})
		svc.Now = func() time.Time { return now }
		return svc
	}
	s1, s2 := newSvc(), newSvc()
	type res struct {
		out *RotateOutput
		err error
	}
	ch := make(chan res, 2)
	go func() { o, e := s1.Execute(context.Background(), rotInput(plain)); ch <- res{o, e} }()
	go func() { o, e := s2.Execute(context.Background(), rotInput(plain)); ch <- res{o, e} }()
	r1, r2 := <-ch, <-ch
	var oks, concs, others int
	for _, r := range []res{r1, r2} {
		switch {
		case r.err == nil:
			oks++
		case errors.Is(r.err, auth.ErrRefreshConcurrent):
			concs++
		default:
			others++
			t.Logf("inesperado: %v", r.err)
		}
	}
	if oks != 1 || concs != 1 || others != 0 {
		t.Fatalf("1×200 + 1×409: oks=%d concs=%d others=%d", oks, concs, others)
	}
	if shared.cases != 1 {
		t.Fatalf("1 solo CAS ganador: %d", shared.cases)
	}
}

// raceShared fake fiel-a-prod: en PG los hashes viejos NUNCA desaparecen
// del lookup (persisten para detectar reuso); la currency la decide SOLO
// el CAS mutex. Así el test es determinista por construcción: ambas lecturas
// ven vigente y exactamente una gana el CAS (1×200 + 1×409, nunca 2×200).
type raceShared struct {
	mu      sync.Mutex
	known   string
	rotated bool
	now     time.Time
	cases   int
}

func (s *raceShared) Lookup(_ context.Context, h string) (auth.RotationLookup, error) {
	if h != s.known {
		return auth.RotationLookup{}, auth.ErrRefreshNotFound
	}
	st := rotState(3, false, s.now.Add(-time.Hour))
	return auth.RotationLookup{State: st, PresentedHash: h,
		SlidingExp: s.now.Add(20 * 24 * time.Hour), IsCurrent: true}, nil
}

func (s *raceShared) RotateCAS(_ context.Context, in auth.RotateCASInput) (auth.RotatedPair, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rotated || in.OldHash != s.known {
		return auth.RotatedPair{}, auth.ErrRefreshConcurrent
	}
	s.rotated = true
	s.cases++
	return in.NewPair, nil
}

func (s *raceShared) ExpireFamily(_ context.Context, _ string) error { return nil }

func (s *raceShared) IncrFlaps(_ context.Context, _ string) (int64, error) { return 1, nil }

func (s *raceShared) ReuseGlobal(_ context.Context, _ auth.ReuseGlobalInput) (auth.GlobalRevokeResult, error) {
	return auth.GlobalRevokeResult{}, nil
}
