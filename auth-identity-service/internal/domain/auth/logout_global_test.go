package auth

import (
	"testing"
	"time"
)

func TestGlobalRevokeResult_Shape(t *testing.T) {
	r := GlobalRevokeResult{Sessions: 3, Families: 3, ValidAfter: time.Now().UTC()}
	if r.Sessions != 3 || r.Families != 3 || r.ValidAfter.IsZero() {
		t.Fatal("shape {Sessions, Families, ValidAfter}")
	}
	var zero GlobalRevokeResult // repeat: 0/0 mismo 200
	if zero.Sessions != 0 || zero.Families != 0 {
		t.Fatal("repeat 0/0")
	}
}

func TestGlobalRate_Buckets(t *testing.T) {
	if LogoutGlobalUserLimit != 5 || LogoutGlobalIPLimit != 20 {
		t.Fatal("buckets 5/hora user + 20/hora ip (Q1)")
	}
	if LogoutGlobalRateWindow != time.Hour {
		t.Fatal("ventana horaria")
	}
}
