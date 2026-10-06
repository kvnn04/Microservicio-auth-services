package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"auth-identity-service/internal/domain/auth"

	"github.com/google/uuid"
)

// --- Fakes CU-SES-03 ---

type fakeSessionVerifier struct {
	claims auth.AccessClaims
	err    error
}

func (f *fakeSessionVerifier) Verify(_ string) (auth.AccessClaims, error) {
	if f.err != nil {
		return auth.AccessClaims{}, f.err
	}
	return f.claims, nil
}

type fakeSessionLister struct {
	views      []auth.SessionView
	listErr    error
	revoked    auth.RevokedOne
	revokeErr  error
	listCalls  int
	revokeCalls int
	lastRevoke [3]string // user, current, target
}

func (f *fakeSessionLister) List(_ context.Context, _ string) ([]auth.SessionView, error) {
	f.listCalls++
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]auth.SessionView, len(f.views))
	copy(out, f.views)
	return out, nil
}

func (f *fakeSessionLister) RevokeOne(_ context.Context, user, current, target string) (auth.RevokedOne, error) {
	f.revokeCalls++
	f.lastRevoke = [3]string{user, current, target}
	if f.revokeErr != nil {
		return auth.RevokedOne{}, f.revokeErr
	}
	return f.revoked, nil
}

type fakeSessionsLimiter struct {
	deny  map[string]bool
	calls []string
}

func (f *fakeSessionsLimiter) Allow(_ context.Context, key string, _ int, _ time.Duration) (bool, time.Duration, error) {
	f.calls = append(f.calls, key)
	if f.deny[key] {
		return false, time.Minute, nil
	}
	return true, 0, nil
}

type sessionsMetricsFake struct {
	counts map[string]int
}

func newSessionsMetricsFake() *sessionsMetricsFake {
	return &sessionsMetricsFake{counts: map[string]int{}}
}
func (m *sessionsMetricsFake) IncListed(r string)              { m.counts["list/"+r]++ }
func (m *sessionsMetricsFake) ObserveListDuration(float64)     {}
func (m *sessionsMetricsFake) IncRevokedOne(r string)          { m.counts["revoke/"+r]++ }
func (m *sessionsMetricsFake) ObserveRevokeOneDuration(float64) {}

type sessionsAuditFake struct {
	calls []map[string]string
}

func (a *sessionsAuditFake) Log(_ context.Context, _ string, fields map[string]string) error {
	a.calls = append(a.calls, fields)
	return nil
}

func sessionClaims(sub, sid string) auth.AccessClaims {
	now := time.Now().UTC()
	return auth.AccessClaims{
		Iss: "https://auth.example.com", Aud: "api",
		Sub: sub, SID: sid, JTI: "jti-" + sid,
		Iat: now.Add(-time.Minute).Unix(), Exp: now.Add(10 * time.Minute).Unix(),
		AuthTime: now.Add(-time.Hour).Unix(),
	}
}

func threeViews() []auth.SessionView {
	now := time.Now().UTC()
	return []auth.SessionView{
		{SID: "sid-C", DeviceLabel: "Chrome · Windows", IPMasked: "203.0.113.xxx", CreatedAt: now, LastSeen: now},
		{SID: "sid-A", DeviceLabel: "Safari · macOS", IPMasked: "10.0.0.xxx", CreatedAt: now, LastSeen: now.Add(-time.Hour)},
		{SID: "sid-B", DeviceLabel: "Firefox · Linux", IPMasked: "192.168.1.xxx", CreatedAt: now, LastSeen: now.Add(-2 * time.Hour)},
	}
}

func TestListSessions_Table(t *testing.T) {
	uid := uuid.NewString()
	cases := []struct {
		name       string
		setup      func(l *fakeSessionLister)
		bearer     string
		verr       error
		denyKey    string
		wantTotal  int
		wantErr    error
		wantMetric string
	}{
		{"3 masked + orden PG", func(l *fakeSessionLister) { l.views = threeViews() },
			"jwt", nil, "", 3, nil, "list/ok"},
		{"sin Bearer 401", func(l *fakeSessionLister) {}, "", nil, "", 0, auth.ErrLogoutUnauthorized, "list/invalid"},
		{"malo 401", func(l *fakeSessionLister) {}, "jwt", errors.New("bad"), "", 0, auth.ErrLogoutUnauthorized, "list/invalid"},
		{"rate 429", func(l *fakeSessionLister) {}, "jwt", nil, "sessions:list:user:" + uid, 0, auth.ErrRateLimited, "list/rate_limited"},
		{"PG down 500", func(l *fakeSessionLister) { l.listErr = auth.ErrSessionInfra }, "jwt", nil, "", 0, auth.ErrSessionInfra, "list/error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lister := &fakeSessionLister{}
			tc.setup(lister)
			audit := &sessionsAuditFake{}
			metrics := newSessionsMetricsFake()
			lim := &fakeSessionsLimiter{deny: map[string]bool{}}
			if tc.denyKey != "" {
				lim.deny[tc.denyKey] = true
			}
			svc := NewListSessionsService(
				&fakeSessionVerifier{claims: sessionClaims(uid, "sid-A"), err: tc.verr},
				lister, lim, audit, metrics, NoopTracer{})
			out, err := svc.Execute(context.Background(), ListSessionsInput{
				Bearer: tc.bearer, RequestID: uuid.NewString(), IP: "9.9.9.9",
			})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err=%v want %v", err, tc.wantErr)
				}
				if metrics.counts[tc.wantMetric] != 1 {
					t.Fatalf("métrica %q: %v", tc.wantMetric, metrics.counts)
				}
				return
			}
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if out.Total != tc.wantTotal || len(out.Sessions) != tc.wantTotal {
				t.Fatalf("total=%d", out.Total)
			}
			// Current solo A; orden PG preservado (C,A,B por last_seen).
			for _, v := range out.Sessions {
				if (v.SID == "sid-A") != v.Current {
					t.Fatalf("current solo A: %+v", v)
				}
				if v.DeviceLabel == "" || v.IPMasked == "" {
					t.Fatalf("masked: %+v", v)
				}
			}
			if out.Sessions[0].SID != "sid-C" {
				t.Fatalf("orden last_seen DESC: %v", out.Sessions[0].SID)
			}
			if len(audit.calls) != 1 || audit.calls[0]["action"] != "session.list" {
				t.Fatalf("audit list: %v", audit.calls)
			}
		})
	}
}

func TestRevokeSession_Table(t *testing.T) {
	uid := uuid.NewString()
	targetC := uuid.NewString()
	currentSID := uuid.NewString()
	cases := []struct {
		name       string
		setup      func(l *fakeSessionLister)
		bearer     string
		verr       error
		target     string
		deny       bool
		wantSID    string
		wantErr    any
		wantMetric string
		current    string
	}{
		{"remota ok", func(l *fakeSessionLister) {
			l.revoked = auth.RevokedOne{SID: targetC, DeviceLabel: "Chrome · Windows", IPMasked: "1.2.3.xxx"}
		}, "jwt", nil, targetC, false, targetC, nil, "revoke/ok", ""},
		{"actual→USE_LOGOUT", func(l *fakeSessionLister) {}, "jwt", nil, currentSID, false, "", auth.ErrUseLogout, "revoke/use_logout", currentSID},
		{"malforma→400", func(l *fakeSessionLister) {}, "jwt", nil, "no-uuid", false, "", &ValidationError{}, "revoke/invalid", ""},
		{"ajena→404", func(l *fakeSessionLister) { l.revokeErr = auth.ErrSessionNotFound }, "jwt", nil, uuid.NewString(), false, "", auth.ErrSessionNotFound, "revoke/not_found", ""},
		{"muerta→404 igual", func(l *fakeSessionLister) { l.revokeErr = auth.ErrSessionNotFound }, "jwt", nil, uuid.NewString(), false, "", auth.ErrSessionNotFound, "revoke/not_found", ""},
		{"rate 429", func(l *fakeSessionLister) {}, "jwt", nil, targetC, true, "", auth.ErrRateLimited, "revoke/rate_limited", ""},
		{"PG down 500", func(l *fakeSessionLister) { l.revokeErr = auth.ErrSessionInfra }, "jwt", nil, targetC, false, "", auth.ErrSessionInfra, "revoke/error", ""},
		{"sin Bearer 401", func(l *fakeSessionLister) {}, "", nil, targetC, false, "", auth.ErrLogoutUnauthorized, "revoke/invalid", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lister := &fakeSessionLister{}
			tc.setup(lister)
			metrics := newSessionsMetricsFake()
			lim := &fakeSessionsLimiter{deny: map[string]bool{}}
			if tc.deny {
				lim.deny["revoke-one:user:"+uid] = true
			}
			svc := NewRevokeSessionService(
				&fakeSessionVerifier{claims: sessionClaims(uid, orDefault(tc.current, "sid-A")), err: tc.verr},
				lister, lim, metrics, NoopTracer{})
			svc.Sleep = func(time.Duration) {} // jitter determinista en tests
			out, err := svc.Execute(context.Background(), RevokeSessionInput{
				Bearer: tc.bearer, TargetSID: tc.target, RequestID: uuid.NewString(), IP: "9.9.9.9",
			})
			if tc.wantErr != nil {
				switch w := tc.wantErr.(type) {
				case *ValidationError:
					var ve *ValidationError
					if !errors.As(err, &ve) {
						t.Fatalf("400 validation: %v", err)
					}
					_ = w
				default:
					if !errors.Is(err, tc.wantErr.(error)) {
						t.Fatalf("err=%v want %v", err, tc.wantErr)
					}
				}
				if metrics.counts[tc.wantMetric] != 1 {
					t.Fatalf("métrica %q: %v", tc.wantMetric, metrics.counts)
				}
				return
			}
			if err != nil || out.SID != tc.wantSID || out.Status != "revoked" {
				t.Fatalf("err=%v out=%+v", err, out)
			}
			if lister.lastRevoke != [3]string{uid, "sid-A", targetC} {
				t.Fatalf("revoker(user,current,target): %v", lister.lastRevoke)
			}
		})
	}
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func TestRevokeSession_RepeatEs404(t *testing.T) {	// Sin idempotencia por RequestID: el repeat cae en miss→404 (§4.2).
	uid := uuid.NewString()
	lister := &fakeSessionLister{
		revoked: auth.RevokedOne{SID: "x"},
	}
	svc := NewRevokeSessionService(
		&fakeSessionVerifier{claims: sessionClaims(uid, "sid-A")},
		lister, &fakeSessionsLimiter{deny: map[string]bool{}}, newSessionsMetricsFake(), NoopTracer{})
	svc.Sleep = func(time.Duration) {}
	reqID := uuid.NewString()
	target := uuid.NewString()
	if _, err := svc.Execute(context.Background(), RevokeSessionInput{Bearer: "jwt", TargetSID: target, RequestID: reqID}); err != nil {
		t.Fatalf("1º: %v", err)
	}
	lister.revokeErr = auth.ErrSessionNotFound // la 2ª vez ya murió
	if _, err := svc.Execute(context.Background(), RevokeSessionInput{Bearer: "jwt", TargetSID: target, RequestID: reqID}); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("repeat→404: %v", err)
	}
}
