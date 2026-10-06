package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"auth-identity-service/internal/domain/auth"

	"github.com/google/uuid"
)

// --- Fakes CU-SES-01 ---

type fakeLogoutVerifier struct {
	claims auth.AccessClaims
	err    error
	calls  int
}

func (f *fakeLogoutVerifier) Verify(_ string) (auth.AccessClaims, error) {
	f.calls++
	if f.err != nil {
		return auth.AccessClaims{}, f.err
	}
	return f.claims, nil
}

type fakeSessionRevoker struct {
	sidOut   auth.RevokedSession
	sidErr   error
	hashOut  auth.RevokedSession
	hashErr  error
	sidCalls int
	hashCalls int
	lastSID  auth.LogoutIdentity
	lastHash string
}

func (f *fakeSessionRevoker) RevokeSID(_ context.Context, id auth.LogoutIdentity) (auth.RevokedSession, error) {
	f.sidCalls++
	f.lastSID = id
	if f.sidErr != nil {
		return auth.RevokedSession{}, f.sidErr
	}
	return f.sidOut, nil
}

func (f *fakeSessionRevoker) RevokeByRefreshHash(_ context.Context, h string) (auth.RevokedSession, error) {
	f.hashCalls++
	f.lastHash = h
	if f.hashErr != nil {
		return auth.RevokedSession{}, f.hashErr
	}
	return f.hashOut, nil
}

type fakeLogoutLimiter struct {
	deny map[string]bool
	calls []string
}

func newFakeLogoutLimiter() *fakeLogoutLimiter {
	return &fakeLogoutLimiter{deny: map[string]bool{}}
}

func (f *fakeLogoutLimiter) Allow(_ context.Context, key string, _ int, _ time.Duration) (bool, time.Duration, error) {
	f.calls = append(f.calls, key)
	if f.deny[key] {
		return false, time.Second, nil
	}
	return true, 0, nil
}

type logoutMetricsFake struct {
	counts map[string]int
	durs   int
}

func newLogoutMetricsFake() *logoutMetricsFake {
	return &logoutMetricsFake{counts: map[string]int{}}
}
func (m *logoutMetricsFake) IncLogout(r string)             { m.counts[r]++ }
func (m *logoutMetricsFake) ObserveLogoutDuration(float64) { m.durs++ }
func (m *logoutMetricsFake) SetDenylistSize(float64)        {}

type logoutFixture struct {
	svc      *LogoutService
	verifier *fakeLogoutVerifier
	revoker  *fakeSessionRevoker
	limiter  *fakeLogoutLimiter
	idem     *mockIdem
	metrics  *logoutMetricsFake
}

func newLogoutFixture(claims auth.AccessClaims) *logoutFixture {
	ver := &fakeLogoutVerifier{claims: claims}
	now := time.Now().UTC()
	rev := &fakeSessionRevoker{
		sidOut: auth.RevokedSession{
			Result: auth.LogoutLoggedOut,
			Identity: auth.LogoutIdentity{
				UserID: claims.Sub, SID: claims.SID, JTI: claims.JTI,
				Family: "fam-1", ExpiresAt: now.Add(5 * time.Minute),
			},
		},
		hashOut: auth.RevokedSession{
			Result: auth.LogoutLoggedOut,
			Identity: auth.LogoutIdentity{
				UserID: "u-refresh", SID: "sid-r", JTI: "jti-r",
				Family: "fam-r", ExpiresAt: now.Add(5 * time.Minute),
			},
		},
	}
	lim := newFakeLogoutLimiter()
	idem := newMockIdem()
	metrics := newLogoutMetricsFake()
	svc := NewLogoutService(ver, rev, lim, idem, metrics, NoopTracer{})
	return &logoutFixture{svc: svc, verifier: ver, revoker: rev, limiter: lim, idem: idem, metrics: metrics}
}

func logoutClaims() auth.AccessClaims {
	now := time.Now().UTC()
	return auth.AccessClaims{
		Iss: "https://auth.example.com", Aud: "api",
		Sub: "user-1", SID: "sid-1", JTI: "jti-1",
		Iat: now.Add(-time.Minute).Unix(), Exp: now.Add(10 * time.Minute).Unix(),
		AuthTime: now.Add(-time.Hour).Unix(),
	}
}

func TestLogout_Table(t *testing.T) {
	now := time.Now().UTC()
	validRefresh := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq" // 43ch base64url
	cases := []struct {
		name       string
		setup      func(f *logoutFixture)
		in         func() LogoutInput
		wantStatus string
		wantErr    error
		wantMetric string
	}{
		{
			name: "ok triple-capa Bearer",
			setup: func(f *logoutFixture) {},
			in: func() LogoutInput {
				return LogoutInput{Bearer: "jwt-ok", RequestID: uuid.NewString(), IP: "1.1.1.1"}
			},
			wantStatus: "logged_out", wantMetric: "ok",
		},
		{
			name: "already mismo 200 (sesión muerta)",
			setup: func(f *logoutFixture) {
				f.revoker.sidOut = auth.RevokedSession{
					Result: auth.LogoutAlreadyLoggedOut,
					Identity: auth.LogoutIdentity{
						UserID: "user-1", SID: "sid-1", JTI: "jti-1",
						Family: "fam-1", ExpiresAt: now.Add(5 * time.Minute),
					},
				}
			},
			in: func() LogoutInput {
				return LogoutInput{Bearer: "jwt-old", RequestID: uuid.NewString(), IP: "1.1.1.1"}
			},
			wantStatus: "already_logged_out", wantMetric: "already",
		},
		{
			name: "Bearer malo 401 sin revocar",
			setup: func(f *logoutFixture) {
				f.verifier.err = errors.New("bad signature")
			},
			in: func() LogoutInput {
				return LogoutInput{Bearer: "jwt-malo", RequestID: uuid.NewString(), IP: "1.1.1.1"}
			},
			wantErr: auth.ErrLogoutUnauthorized, wantMetric: "invalid",
		},
		{
			name: "Bearer expirado 401",
			setup: func(f *logoutFixture) {
				f.verifier.err = errors.New("expired")
			},
			in: func() LogoutInput {
				return LogoutInput{Bearer: "jwt-exp", RequestID: uuid.NewString(), IP: "1.1.1.1"}
			},
			wantErr: auth.ErrLogoutUnauthorized, wantMetric: "invalid",
		},
		{
			name: "refresh-alt ok sin Bearer",
			setup: func(f *logoutFixture) {},
			in: func() LogoutInput {
				return LogoutInput{RefreshToken: validRefresh, RequestID: uuid.NewString(), IP: "2.2.2.2"}
			},
			wantStatus: "logged_out", wantMetric: "ok",
		},
		{
			name: "sin nada 401",
			setup: func(f *logoutFixture) {},
			in: func() LogoutInput {
				return LogoutInput{RequestID: uuid.NewString(), IP: "3.3.3.3"}
			},
			wantErr: auth.ErrLogoutUnauthorized, wantMetric: "invalid",
		},
		{
			name: "refresh malformado 401",
			setup: func(f *logoutFixture) {},
			in: func() LogoutInput {
				return LogoutInput{RefreshToken: "corto", RequestID: uuid.NewString(), IP: "2.2.2.2"}
			},
			wantErr: auth.ErrLogoutUnauthorized, wantMetric: "invalid",
		},
		{
			name: "rate user 429 sin revocar",
			setup: func(f *logoutFixture) {
				f.limiter.deny["logout:user:user-1"] = true
			},
			in: func() LogoutInput {
				return LogoutInput{Bearer: "jwt-ok", RequestID: uuid.NewString(), IP: "1.1.1.1"}
			},
			wantErr: auth.ErrRateLimited, wantMetric: "rate_limited",
		},
		{
			name: "PG down 500",
			setup: func(f *logoutFixture) {
				f.revoker.sidErr = auth.ErrSessionInfra
			},
			in: func() LogoutInput {
				return LogoutInput{Bearer: "jwt-ok", RequestID: uuid.NewString(), IP: "1.1.1.1"}
			},
			wantErr: auth.ErrSessionInfra, wantMetric: "error",
		},
		{
			name: "NotFound del revoker → already 200",
			setup: func(f *logoutFixture) {
				f.revoker.sidErr = auth.ErrLogoutNotFound
			},
			in: func() LogoutInput {
				return LogoutInput{Bearer: "jwt-ok", RequestID: uuid.NewString(), IP: "1.1.1.1"}
			},
			wantStatus: "already_logged_out", wantMetric: "already",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newLogoutFixture(logoutClaims())
			tc.setup(f)
			in := tc.in()
			out, err := f.svc.Execute(context.Background(), in)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err=%v want %v", err, tc.wantErr)
				}
				if f.metrics.counts[tc.wantMetric] != 1 {
					t.Fatalf("métrica %q: %v", tc.wantMetric, f.metrics.counts)
				}
				return
			}
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if out.Status != tc.wantStatus {
				t.Fatalf("status=%q want %q", out.Status, tc.wantStatus)
			}
			if f.metrics.counts[tc.wantMetric] != 1 {
				t.Fatalf("métrica %q: %v", tc.wantMetric, f.metrics.counts)
			}
			// Auditoría sin tokens: la escribe el Revoker en su Tx
			// (cubierta en el test de integración PG, no aquí).
		})
	}
}

func TestLogout_ReplayRequestID_UnaSolaRevocacion(t *testing.T) {
	f := newLogoutFixture(logoutClaims())
	reqID := uuid.NewString()
	in := LogoutInput{Bearer: "jwt-ok", RequestID: reqID, IP: "1.1.1.1"}
	out1, err := f.svc.Execute(context.Background(), in)
	if err != nil || out1.Status != "logged_out" {
		t.Fatalf("1º: %v %+v", err, out1)
	}
	out2, err := f.svc.Execute(context.Background(), in)
	if err != nil || out2.Status != "logged_out" {
		t.Fatalf("replay: %v %+v", err, out2)
	}
	if f.revoker.sidCalls != 1 {
		t.Fatalf("replay no debe re-revocar: %d", f.revoker.sidCalls)
	}
}

func TestLogout_RefreshHash_SeHashea(t *testing.T) {
	f := newLogoutFixture(logoutClaims())
	plain := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"
	in := LogoutInput{RefreshToken: plain, RequestID: uuid.NewString(), IP: "9.9.9.9"}
	if _, err := f.svc.Execute(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if len(f.revoker.lastHash) != 64 {
		t.Fatalf("hash hex 64ch: %q", f.revoker.lastHash)
	}
	if f.revoker.lastHash == plain {
		t.Fatal("nunca plano al revoker")
	}
}

func TestLogout_BearerConPrefijo(t *testing.T) {
	f := newLogoutFixture(logoutClaims())
	in := LogoutInput{Bearer: "Bearer jwt-ok", RequestID: uuid.NewString(), IP: "1.1.1.1"}
	out, err := f.svc.Execute(context.Background(), in)
	if err != nil || out.Status != "logged_out" {
		t.Fatalf("%v %+v", err, out)
	}
}
