package auth

import (
	"testing"
)

func TestMaskIP(t *testing.T) {
	cases := []struct{ in, want string }{
		{"203.0.113.42", "203.0.113.xxx"},
		{" 203.0.113.42 ", "203.0.113.xxx"},
		{"10.0.0.1:8081", "10.0.0.xxx"},
		{"", "unknown"},
		{"no-es-ip", "unknown"},
		{"2001:db8:abcd:12::0", "2001:db8:abcd:12::xxxx"},
		{"::1", "0:0:0:0::xxxx"},
		{"fe80::1%eth0", "fe80:0:0:0::xxxx"},
	}
	for _, tc := range cases {
		got := MaskIP(tc.in)
		if got != tc.want {
			t.Errorf("MaskIP(%q)=%q want %q", tc.in, got, tc.want)
		}
		// Nunca expone el último grupo/octeto completo.
		if tc.want != "unknown" && got == tc.in {
			t.Errorf("MaskIP(%q) sin enmascarar", tc.in)
		}
	}
}

func TestDeviceLabel(t *testing.T) {
	chromeWin := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	if got := DeviceLabel(chromeWin); got != "Chrome · Windows" {
		t.Fatalf("chrome/win: %q", got)
	}
	edge := "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36 Edg/126.0.0.0"
	if got := DeviceLabel(edge); got != "Edge · Windows" {
		t.Fatalf("edge antes que chrome: %q", got)
	}
	ffLin := "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0"
	if got := DeviceLabel(ffLin); got != "Firefox · Linux" {
		t.Fatalf("firefox/linux: %q", got)
	}
	safariMac := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
	if got := DeviceLabel(safariMac); got != "Safari · macOS" {
		t.Fatalf("safari/macos: %q", got)
	}
	if got := DeviceLabel(""); got != "unknown" {
		t.Fatalf("vacío: %q", got)
	}
	if got := DeviceLabel("curl/8.0"); got != "curl · desconocido" {
		t.Fatalf("curl: %q", got)
	}
	// Sin UA crudo en el label.
	if got := DeviceLabel(chromeWin); len(got) > 60 {
		t.Fatalf("label acotado: %q", got)
	}
}

func TestSessionView_NoTokens(t *testing.T) {
	// Compilación como contrato: la vista NO tiene campos sensibles.
	v := SessionView{SID: "s", DeviceLabel: "Chrome · Windows", IPMasked: "1.2.3.xxx"}
	if v.SID == "" || v.DeviceLabel == "" || v.IPMasked == "" {
		t.Fatal("shape pública")
	}
}
