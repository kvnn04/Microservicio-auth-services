package user

import (
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
)

var emailRegex = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]{2,}$`)

// Normalize aplica la normalización canónica CU-REG-01 §3 paso 3:
// trim, lowercase folding, IDN a punycode, longitud ≤254 ASCII,
// formato RFC5322 simplificado, rechazo control/nulos, solo ASCII tras punycode.
// NO elimina +tag ni puntos locales.
func Normalize(raw string) (normalized string, original string, err error) {
	original = strings.TrimSpace(raw)
	if original == "" {
		return "", "", fmt.Errorf("%w: empty", ErrInvalidEmail)
	}
	for _, r := range original {
		if r == 0 || unicode.IsControl(r) {
			return "", "", fmt.Errorf("%w: control characters not allowed", ErrInvalidEmail)
		}
	}
	folded := strings.ToLower(original)
	local, domain, found := strings.Cut(folded, "@")
	if found {
		asciiDomain, convErr := idna.Lookup.ToASCII(domain)
		if convErr != nil {
			return "", "", fmt.Errorf("%w: idn conversion failed", ErrInvalidEmail)
		}
		folded = local + "@" + asciiDomain
	}
	if len(folded) > 254 {
		return "", "", ErrEmailTooLong
	}
	if len(folded) < 5 {
		return "", "", fmt.Errorf("%w: too short", ErrInvalidEmail)
	}
	// Solo ASCII tras punycode: emojis / unicode en local → 400.
	for _, r := range folded {
		if r > 127 {
			return "", "", fmt.Errorf("%w: non-ascii not allowed", ErrInvalidEmail)
		}
	}
	if !emailRegex.MatchString(folded) {
		return "", "", fmt.Errorf("%w: format", ErrInvalidEmail)
	}
	if _, parseErr := mail.ParseAddress(folded); parseErr != nil {
		return "", "", fmt.Errorf("%w: %v", ErrInvalidEmail, parseErr)
	}
	return folded, original, nil
}

// DomainOf retorna el dominio (para logs/telemetría sin PII completa).
func DomainOf(normalized string) string {
	_, domain, found := strings.Cut(normalized, "@")
	if !found {
		return ""
	}
	return domain
}
