package auth

import (
	"testing"
	"time"
)

func TestDenylistTTL_Clamp(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cases := []struct {
		name string
		exp  time.Time
		want time.Duration
	}{
		{"restante 5min", now.Add(5 * time.Minute), 5 * time.Minute},
		{"restante 1s", now.Add(time.Second), time.Second},
		{"expirado hace 1h -> 1s", now.Add(-time.Hour), time.Second},
		{"cero -> 1s", time.Time{}, time.Second},
		{"30min se acota a 15min", now.Add(30 * time.Minute), 15 * time.Minute},
		{"90min se acota a 15min", now.Add(90 * time.Minute), 15 * time.Minute},
		{"sub-segundo -> 1s", now.Add(100 * time.Millisecond), time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DenylistTTL(tc.exp, now); got != tc.want {
				t.Fatalf("TTL=%v want %v", got, tc.want)
			}
		})
	}
}

func TestLogoutIdentity_Validate(t *testing.T) {
	now := time.Now().UTC()
	ok := LogoutIdentity{UserID: "u1", SID: "s1", JTI: "j1", ExpiresAt: now.Add(5 * time.Minute)}
	if err := ok.Validate(); err != nil {
		t.Fatalf("válida: %v", err)
	}
	bad := []LogoutIdentity{
		{},
		{SID: "s", JTI: "j", ExpiresAt: now},
		{UserID: "u", JTI: "j", ExpiresAt: now},
		{UserID: "u", SID: "s", ExpiresAt: now},
		{UserID: "u", SID: "s", JTI: "j"},
	}
	for i, id := range bad {
		if err := id.Validate(); err == nil {
			t.Fatalf("caso %d debía fallar", i)
		}
	}
}

func TestLogoutResult_Values(t *testing.T) {
	if LogoutLoggedOut != "logged_out" || LogoutAlreadyLoggedOut != "already_logged_out" {
		t.Fatal("estados 200 del contrato")
	}
	if LogoutUserLimit != 30 || LogoutIPLimit != 60 {
		t.Fatal("buckets 30/min user + 60/min ip")
	}
	if LogoutRefreshPath != "/api/v1/auth/refresh" {
		t.Fatal("Path MISMO que Issue (RN-05)")
	}
}
