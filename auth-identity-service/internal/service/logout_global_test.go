package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"auth-identity-service/internal/domain/auth"

	"github.com/google/uuid"
)

// --- Fakes CU-SES-02 ---

type fakeGlobalVerifier struct {
	claims auth.AccessClaims
	err    error
	calls  int
}

func (f *fakeGlobalVerifier) Verify(_ string) (auth.AccessClaims, error) {
	f.calls++
	if f.err != nil {
		return auth.AccessClaims{}, f.err
	}
	return f.claims, nil
}

type fakeGlobalRevoker struct {
	out       auth.GlobalRevokeResult
	err       error
	calls     int
	lastUser  string
	lastIP    string
}

func (f *fakeGlobalRevoker) RevokeAll(_ context.Context, userID, ip string) (auth.GlobalRevokeResult, error) {
	f.calls++
	f.lastUser = userID
	f.lastIP = ip
	if f.err != nil {
		return auth.GlobalRevokeResult{}, f.err
	}
	return f.out, nil
}

// fakeGlobalLimiter niega por mapa (429 puntual).
type fakeGlobalLimiter struct {
	deny  map[string]bool
	calls []string
}

func (f *fakeGlobalLimiter) Allow(_ context.Context, key string, _ int, _ time.Duration) (bool, time.Duration, error) {
	f.calls = append(f.calls, key)
	if f.deny[key] {
		return false, time.Minute, nil
	}
	return true, 0, nil
}

// countGlobalLimiter permite N usos por clave (flood 5/hora).
type countGlobalLimiter struct {
	limit  int
	counts map[string]int
}

func (f *countGlobalLimiter) Allow(_ context.Context, key string, _ int, _ time.Duration) (bool, time.Duration, error) {
	if f.counts == nil {
		f.counts = map[string]int{}
	}
	f.counts[key]++
	if f.counts[key] > f.limit {
		return false, time.Hour, nil
	}
	return true, 0, nil
}

type globalMetricsFake struct {
	counts   map[string]int
	durs     int
	revoked  []int
}

func newGlobalMetricsFake() *globalMetricsFake {
	return &globalMetricsFake{counts: map[string]int{}}
}
func (m *globalMetricsFake) IncGlobal(r string)            { m.counts[r]++ }
func (m *globalMetricsFake) ObserveGlobalDuration(float64) { m.durs++ }
func (m *globalMetricsFake) ObserveSessionsRevoked(n int)  { m.revoked = append(m.revoked, n) }

type globalFixture struct {
	svc      *LogoutGlobalService
	verifier *fakeGlobalVerifier
	revoker  *fakeGlobalRevoker
	limiter  *fakeGlobalLimiter
	idem     *mockIdem
	metrics  *globalMetricsFake
}

func globalClaims() auth.AccessClaims {
	now := time.Now().UTC()
	return auth.AccessClaims{
		Iss: "https://auth.example.com", Aud: "api",
		Sub: "user-9", SID: "sid-9", JTI: "jti-9",
		Iat: now.Add(-time.Minute).Unix(), Exp: now.Add(10 * time.Minute).Unix(),
		AuthTime: now.Add(-time.Hour).Unix(),
	}
}

func newGlobalFixture() *globalFixture {
	ver := &fakeGlobalVerifier{claims: globalClaims()}
	rev := &fakeGlobalRevoker{out: auth.GlobalRevokeResult{Sessions: 3, Families: 3, ValidAfter: time.Now().UTC()}}
	lim := &fakeGlobalLimiter{deny: map[string]bool{}}
	idem := newMockIdem()
	metrics := newGlobalMetricsFake()
	svc := NewLogoutGlobalService(ver, rev, lim, idem, metrics, NoopTracer{})
	return &globalFixture{svc: svc, verifier: ver, revoker: rev, limiter: lim, idem: idem, metrics: metrics}
}

func TestLogoutGlobal_Table(t *testing.T) {
	cases := []struct {
		name       string
		setup      func(f *globalFixture)
		in         func() LogoutGlobalInput
		wantStatus string
		wantN      int
		wantErr    error
		wantMetric string
		wantCalls  int // llamadas esperadas al Revoker
	}{
		{
			name: "corte 3 vivas",
			setup: func(f *globalFixture) {},
			in: func() LogoutGlobalInput {
				return LogoutGlobalInput{Bearer: "jwt-A", RequestID: uuid.NewString(), IP: "1.1.1.1"}
			},
			wantStatus: "logged_out_global", wantN: 3, wantMetric: "ok",
		},
		{
			name: "repeat 0 vivas mismo 200",
			setup: func(f *globalFixture) {
				f.revoker.out = auth.GlobalRevokeResult{Sessions: 0, Families: 0, ValidAfter: time.Now().UTC()}
			},
			in: func() LogoutGlobalInput {
				return LogoutGlobalInput{Bearer: "jwt-A", RequestID: uuid.NewString(), IP: "1.1.1.1"}
			},
			wantStatus: "logged_out_global", wantN: 0, wantMetric: "ok",
		},
		{
			name: "Bearer malo 401 sin revocar",
			setup: func(f *globalFixture) {
				f.verifier.err = errors.New("bad signature")
			},
			in: func() LogoutGlobalInput {
				return LogoutGlobalInput{Bearer: "jwt-malo", RequestID: uuid.NewString(), IP: "1.1.1.1"}
			},
			wantErr: auth.ErrLogoutUnauthorized, wantMetric: "invalid",
		},
		{
			name: "expirado 401 sin revocar",
			setup: func(f *globalFixture) {
				f.verifier.err = errors.New("expired")
			},
			in: func() LogoutGlobalInput {
				return LogoutGlobalInput{Bearer: "jwt-exp", RequestID: uuid.NewString(), IP: "1.1.1.1"}
			},
			wantErr: auth.ErrLogoutUnauthorized, wantMetric: "invalid",
		},
		{
			name: "sin Bearer 401",
			setup: func(f *globalFixture) {},
			in: func() LogoutGlobalInput {
				return LogoutGlobalInput{RequestID: uuid.NewString(), IP: "1.1.1.1"}
			},
			wantErr: auth.ErrLogoutUnauthorized, wantMetric: "invalid",
		},
		{
			name: "rate user 429 sin cortar",
			setup: func(f *globalFixture) {
				f.limiter.deny["logout-global:user:user-9"] = true
			},
			in: func() LogoutGlobalInput {
				return LogoutGlobalInput{Bearer: "jwt-A", RequestID: uuid.NewString(), IP: "1.1.1.1"}
			},
			wantErr: auth.ErrRateLimited, wantMetric: "rate_limited",
		},
		{
			name: "usuario borrado 401",
			setup: func(f *globalFixture) {
				f.revoker.err = auth.ErrGlobalUserNotFound
			},
			in: func() LogoutGlobalInput {
				return LogoutGlobalInput{Bearer: "jwt-A", RequestID: uuid.NewString(), IP: "1.1.1.1"}
			},
			wantErr: auth.ErrLogoutUnauthorized, wantMetric: "invalid",
			wantCalls: 1,
		},
		{
			name: "PG down 500",
			setup: func(f *globalFixture) {
				f.revoker.err = auth.ErrSessionInfra
			},
			in: func() LogoutGlobalInput {
				return LogoutGlobalInput{Bearer: "jwt-A", RequestID: uuid.NewString(), IP: "1.1.1.1"}
			},
			wantErr: auth.ErrSessionInfra, wantMetric: "error",
			wantCalls: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newGlobalFixture()
			tc.setup(f)
			before := f.revoker.calls
			out, err := f.svc.Execute(context.Background(), tc.in())
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err=%v want %v", err, tc.wantErr)
				}
				if f.revoker.calls != before+tc.wantCalls {
					t.Fatalf("revoker calls=%d want %d", f.revoker.calls, before+tc.wantCalls)
				}
				if f.metrics.counts[tc.wantMetric] != 1 {
					t.Fatalf("métrica %q: %v", tc.wantMetric, f.metrics.counts)
				}
				return
			}
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if out.Status != tc.wantStatus || out.SessionsRevoked != tc.wantN {
				t.Fatalf("out=%+v", out)
			}
			if f.metrics.counts[tc.wantMetric] != 1 {
				t.Fatalf("métrica %q: %v", tc.wantMetric, f.metrics.counts)
			}
			if len(f.metrics.revoked) != 1 || f.metrics.revoked[0] != tc.wantN {
				t.Fatalf("histograma: %v", f.metrics.revoked)
			}
			if f.revoker.lastUser != "user-9" || f.revoker.lastIP == "" {
				t.Fatalf("revoker(user,ip): %q %q", f.revoker.lastUser, f.revoker.lastIP)
			}
		})
	}
}

func TestLogoutGlobal_ReplayRequestID_SinRebump(t *testing.T) {
	f := newGlobalFixture()
	in := LogoutGlobalInput{Bearer: "jwt-A", RequestID: uuid.NewString(), IP: "1.1.1.1"}
	out1, err := f.svc.Execute(context.Background(), in)
	if err != nil || out1.SessionsRevoked != 3 {
		t.Fatalf("1º: %v %+v", err, out1)
	}
	out2, err := f.svc.Execute(context.Background(), in)
	if err != nil || out2.SessionsRevoked != 3 {
		t.Fatalf("replay: %v %+v", err, out2)
	}
	if f.revoker.calls != 1 {
		t.Fatalf("replay no re-bumpea: %d", f.revoker.calls)
	}
}

func TestLogoutGlobal_Flood_5x200_Resto429(t *testing.T) {
	ver := &fakeGlobalVerifier{claims: globalClaims()}
	rev := &fakeGlobalRevoker{out: auth.GlobalRevokeResult{Sessions: 1, Families: 1, ValidAfter: time.Now().UTC()}}
	lim := &countGlobalLimiter{limit: 5}
	svc := NewLogoutGlobalService(ver, rev, lim, newMockIdem(), newGlobalMetricsFake(), NoopTracer{})
	var ok, limited int
	for i := 0; i < 7; i++ {
		_, err := svc.Execute(context.Background(), LogoutGlobalInput{
			Bearer: "jwt-A", RequestID: uuid.NewString(), IP: "9.9.9.9",
		})
		if err == nil {
			ok++
		} else if errors.Is(err, auth.ErrRateLimited) {
			limited++
		} else {
			t.Fatalf("iter %d: %v", i, err)
		}
	}
	if ok != 5 || limited != 2 {
		t.Fatalf("5×200 + 2×429: ok=%d limited=%d", ok, limited)
	}
	if rev.calls != 5 {
		t.Fatalf("sin cortar en 429: %d", rev.calls)
	}
}
