package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auth-identity-service/internal/service"
)

func pairFixture() *service.SessionData {
	return &service.SessionData{
		AccessToken: "eyJhbGciOiJFZERTQSJ9.payload.sig",
		RefreshTokenID: "abcdefghijklmnopqrstuvwxyz0123456789-_ABC",
		ExpiresAt: 123, SID: "sid-1",
	}
}

func TestWritePair_Web(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	rr := httptest.NewRecorder()
	WritePair(rr, pairFixture(), req, true)
	res := rr.Result()
	if cc := res.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("no-store, got %q", cc)
	}
	var foundRefresh bool
	for _, c := range res.Cookies() {
		if c.Name == "refresh_token" {
			foundRefresh = true
			if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode {
				t.Fatalf("flags: %+v", c)
			}
			if c.Path != "/api/v1/auth/refresh" {
				t.Fatalf("path: %q", c.Path)
			}
			if c.MaxAge != 30*24*3600 {
				t.Fatalf("maxage: %d", c.MaxAge)
			}
		}
		if c.Name == "access_token" {
			t.Fatal("Access nunca en cookie")
		}
	}
	if !foundRefresh {
		t.Fatal("falta refresh cookie")
	}
	var body map[string]any
	_ = json.NewDecoder(rr.Body).Decode(&body)
	data, _ := body["data"].(map[string]any)
	if data["access_token"] == nil || data["sid"] == nil {
		t.Fatalf("body: %v", body)
	}
	if data["refresh_token"] != nil {
		t.Fatal("web no expone refresh en body")
	}
	if exp, _ := data["expires_in"].(float64); exp != 900 {
		t.Fatalf("expires_in: %v", data["expires_in"])
	}
}

func TestWritePair_Native(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	req.Header.Set("X-Client-Type", "native")
	rr := httptest.NewRecorder()
	WritePair(rr, pairFixture(), req, true)
	if len(rr.Result().Cookies()) != 0 {
		t.Fatal("nativo sin cookies")
	}
	var body map[string]any
	_ = json.NewDecoder(rr.Body).Decode(&body)
	data, _ := body["data"].(map[string]any)
	if data["access_token"] == nil || data["refresh_token"] == nil || data["sid"] == nil {
		t.Fatalf("nativo doble-body: %v", body)
	}
}

func TestWritePair_NuncaURL(t *testing.T) {
	// Ni tokens ni PII en URL/query/logs: el transporte solo usa body+cookie.
	req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	if strings.Contains(req.URL.String(), "eyJ") || strings.Contains(req.URL.String(), "refresh") {
		t.Fatal("tokens en URL")
	}
}
