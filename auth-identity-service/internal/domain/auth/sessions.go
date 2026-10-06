package auth

import (
	"net"
	"strings"
	"time"
)

// Constantes CU-SES-03: lectura y bisturí de sesiones propias.
// Rate: lista 60/min (user+IP), revoke-one 20/hora (solo user, frena
// flood de cierres ajenos sin castigar lecturas).
const (
	ListUserLimit      = 60
	ListIPLimit        = 60
	RevokeOneUserLimit = 20
	ListRateWindow     = time.Minute
	RevokeOneWindow    = time.Hour
	// TouchDebounce evita escribir last_seen más de 1 vez / 5min / sid.
	TouchDebounce = 5 * time.Minute
	// JitterNotFound ±10-20ms para que el 404 no filtre hit/miss por tiempo.
	JitterNotFoundMin = 10 * time.Millisecond
	JitterNotFoundMax = 20 * time.Millisecond
)

// SessionView fila pública de sesión (sin jti/family/tokens/hashes).
// Current la marca el servicio (sid == Bearer.sid); el adapter no decide.
type SessionView struct {
	SID         string
	DeviceLabel string
	IPMasked    string
	Location    string // "" = sin GeoIP (contrato: null)
	CreatedAt   time.Time
	LastSeen    time.Time
	Current     bool
}

// MaskIP enmascara para mostrar al dueño sin exponerla completa:
// v4 "203.0.113.42" → "203.0.113.xxx"; v6 → /64 + "::xxxx".
// Entrada inválida/vacía → "unknown" (nunca cadena vacía al DTO).
func MaskIP(ip string) string {
	s := strings.TrimSpace(ip)
	if s == "" {
		return "unknown"
	}
	// Quita puerto ":8081" y zona "%eth0" antes de parsear.
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	if i := strings.Index(s, "%"); i >= 0 {
		s = s[:i]
	}
	parsed := net.ParseIP(s)
	if parsed == nil {
		return "unknown"
	}
	if v4 := parsed.To4(); v4 != nil {
		return strings.Join([]string{
			itoaByte(v4[0]), itoaByte(v4[1]), itoaByte(v4[2]), "xxx",
		}, ".")
	}
	// v6: primeros 64 bits + sufijo fijo (sin IID real).
	buf := parsed.To16()
	groups := make([]string, 0, 4)
	for i := 0; i < 8; i += 2 {
		groups = append(groups, hexGroup(buf[i], buf[i+1]))
	}
	return strings.Join(groups, ":") + "::xxxx"
}

// DeviceLabel resume UA en "Familia · SO" sin exponer el UA crudo.
// Heurística sin dependencias (orden importa: Edge/Opera contienen Chrome).
func DeviceLabel(ua string) string {
	s := strings.TrimSpace(ua)
	if s == "" {
		return "unknown"
	}
	l := strings.ToLower(s)
	fam := "Navegador"
	switch {
	case strings.Contains(l, "edg/") || strings.Contains(l, "edge/"):
		fam = "Edge"
	case strings.Contains(l, "opr/") || strings.Contains(l, "opera"):
		fam = "Opera"
	case strings.Contains(l, "chrome/") && !strings.Contains(l, "chromium"):
		fam = "Chrome"
	case strings.Contains(l, "chromium"):
		fam = "Chromium"
	case strings.Contains(l, "firefox/") || strings.Contains(l, "fxios/"):
		fam = "Firefox"
	case strings.Contains(l, "safari/") && strings.Contains(l, "version/"):
		fam = "Safari"
	case strings.Contains(l, "curl/"):
		fam = "curl"
	case strings.Contains(l, "k6"):
		fam = "k6"
	case strings.Contains(l, "okhttp/"):
		fam = "okhttp"
	}
	os := "desconocido"
	switch {
	case strings.Contains(l, "windows nt"):
		os = "Windows"
	case strings.Contains(l, "android"):
		os = "Android"
	case strings.Contains(l, "iphone") || strings.Contains(l, "ipad"):
		os = "iOS"
	case strings.Contains(l, "mac os x") || strings.Contains(l, "macintosh"):
		os = "macOS"
	case strings.Contains(l, "linux"):
		os = "Linux"
	}
	if fam == "Navegador" && os == "desconocido" {
		return "unknown"
	}
	return fam + " · " + os
}

func itoaByte(b byte) string {
	if b < 10 {
		return string([]byte{'0' + b})
	}
	if b < 100 {
		return string([]byte{'0' + b/10, '0' + b%10})
	}
	return string([]byte{'0' + b/100, '0' + (b/10)%10, '0' + b%10})
}

func hexGroup(hi, lo byte) string {
	const digits = "0123456789abcdef"
	v := int(hi)<<8 | int(lo)
	if v == 0 {
		return "0"
	}
	var b [4]byte
	i := 4
	for v > 0 {
		i--
		b[i] = digits[v&0xf]
		v >>= 4
	}
	return string(b[i:])
}
