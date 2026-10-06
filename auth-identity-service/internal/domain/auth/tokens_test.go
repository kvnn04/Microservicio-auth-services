package auth

import (
	"testing"
	"time"
)

func TestNewAccessClaims_TTLExacto(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	authTime := now.Add(-time.Second)
	c, err := NewAccessClaims("", "", "user-1", "sid-1", "jti-1", authTime, []AMR{AMRPassword}, nil, 3, now)
	if err != nil {
		t.Fatalf("claims: %v", err)
	}
	if c.Exp-c.Iat != 900 {
		t.Fatalf("TTL debe ser 900s, got %d", c.Exp-c.Iat)
	}
	if c.Aud != "api" || c.Iss != DefaultIssuer {
		t.Fatalf("iss/aud por defecto: %+v", c)
	}
	if len(c.AMR) != 1 || c.AMR[0] != "pwd" {
		t.Fatalf("amr exacto: %v", c.AMR)
	}
	if len(c.Roles) != 1 || c.Roles[0] != "user" {
		t.Fatalf("roles default: %v", c.Roles)
	}
	if c.TokenVer != 1 {
		t.Fatalf("token_ver=1: %d", c.TokenVer)
	}
	if c.AuthTime != authTime.Unix() {
		t.Fatalf("auth_time debe ser instante auth completa")
	}
}

func TestNewAccessClaims_Table(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name    string
		sub     string
		sid     string
		jti     string
		amr     []AMR
		roles   []string
		wantErr bool
	}{
		{"happy pwd", "u1", "s1", "j1", []AMR{AMRPassword}, []string{"user"}, false},
		{"happy mfa", "u1", "s1", "j1", []AMR{AMRPassword, AMRTOTP}, []string{"user", "admin"}, false},
		{"happy federated", "u1", "s1", "j1", []AMR{AMRFederatedGoogle}, nil, false},
		{"sin sub", "", "s1", "j1", []AMR{AMRPassword}, nil, true},
		{"sin sid", "u1", "", "j1", []AMR{AMRPassword}, nil, true},
		{"sin jti", "u1", "s1", "", []AMR{AMRPassword}, nil, true},
		{"sin amr", "u1", "s1", "j1", nil, nil, true},
		{"amr desconocido", "u1", "s1", "j1", []AMR{AMR("weird")}, nil, true},
		{"roles exceso", "u1", "s1", "j1", []AMR{AMRPassword}, make([]string, 65), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewAccessClaims("", "", tc.sub, tc.sid, tc.jti, now, tc.amr, tc.roles, 0, now)
			if (err != nil) != tc.wantErr {
				t.Fatalf("wantErr=%v got=%v", tc.wantErr, err)
			}
		})
	}
}

func TestSessionRequest_Validate(t *testing.T) {
	now := time.Now().UTC()
	dev := Device{IPHash: "ip", UAHash: "ua"}
	cases := []struct {
		name    string
		req     SessionRequest
		wantErr bool
	}{
		{"password ok", SessionRequest{UserID: "u1", Method: MethodPassword, AMR: []AMR{AMRPassword}, AuthTime: now, Device: dev}, false},
		{"mfa ok", SessionRequest{UserID: "u1", Method: MethodPassword, AMR: []AMR{AMRPassword, AMRTOTP}, AuthTime: now, Device: dev}, false},
		{"backup ok", SessionRequest{UserID: "u1", Method: MethodPassword, AMR: []AMR{AMRPassword, AMRBackup}, AuthTime: now, Device: dev}, false},
		{"federated ok", SessionRequest{UserID: "u1", Method: MethodFederatedGoogle, AMR: []AMR{AMRFederatedGoogle}, AuthTime: now, Device: dev}, false},
		{"sin user", SessionRequest{Method: MethodPassword, AMR: []AMR{AMRPassword}, AuthTime: now, Device: dev}, true},
		{"method desconocido", SessionRequest{UserID: "u1", Method: "weird", AMR: []AMR{AMRPassword}, AuthTime: now, Device: dev}, true},
		{"amr vacio", SessionRequest{UserID: "u1", Method: MethodPassword, AuthTime: now, Device: dev}, true},
		{"amr incoherente pwd sin pwd", SessionRequest{UserID: "u1", Method: MethodPassword, AMR: []AMR{AMRFederatedGoogle}, AuthTime: now, Device: dev}, true},
		{"amr incoherente fed sin fed", SessionRequest{UserID: "u1", Method: MethodFederatedGoogle, AMR: []AMR{AMRPassword}, AuthTime: now, Device: dev}, true},
		{"device vacio", SessionRequest{UserID: "u1", Method: MethodPassword, AMR: []AMR{AMRPassword}, AuthTime: now}, true},
		{"authtime cero", SessionRequest{UserID: "u1", Method: MethodPassword, AMR: []AMR{AMRPassword}, Device: dev}, true},
		{"authtime futuro", SessionRequest{UserID: "u1", Method: MethodPassword, AMR: []AMR{AMRPassword}, AuthTime: now.Add(time.Hour), Device: dev}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.req.ValidateRequest(now); (err != nil) != tc.wantErr {
				t.Fatalf("wantErr=%v got=%v", tc.wantErr, err)
			}
		})
	}
}

func TestConsts(t *testing.T) {
	if AccessTTL != 15*time.Minute {
		t.Fatal("AccessTTL 15m")
	}
	if RefreshSlidingTTL != 30*24*time.Hour {
		t.Fatal("sliding 30d")
	}
	if RefreshAbsoluteTTL != 90*24*time.Hour {
		t.Fatal("absolute 90d")
	}
	if RefreshAbsoluteTTL <= RefreshSlidingTTL {
		t.Fatal("absolute>sliding")
	}
	if RefreshBytes != 32 {
		t.Fatal("32B")
	}
	if MaxSessionsPerUser != 20 {
		t.Fatal("20 sesiones")
	}
}
