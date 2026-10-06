package auth

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

var (
	ErrPasswordTooShort   = errors.New("password too short")
	ErrPasswordTooLong    = errors.New("password too long")
	ErrPasswordMissingCls = errors.New("password missing character class")
	ErrPasswordRepeating  = errors.New("password has trivial repeating sequence")
	ErrPasswordEqualsMail = errors.New("password must not equal email local part")
	ErrPasswordCompromisd = errors.New("password found in breach corpus")
	ErrPasswordHasControl = errors.New("password contains control characters")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountBlocked     = errors.New("account blocked")
	ErrInvalidGoogleToken = errors.New("invalid google token")
	ErrRateLimited        = errors.New("rate limited")
	ErrValidation         = errors.New("validation failed")
	ErrInfra              = errors.New("infrastructure failure")
	ErrDuplicateShadow    = errors.New("duplicate shadow")
)

// ValidateSyntax valida política CU-REG-01 §3 paso 4 SIN I/O (pura).
func ValidateSyntax(passwordInput, emailLocalPart string) error {
	pw := norm.NFKC.String(passwordInput)
	runeCount := utf8.RuneCountInString(pw)
	if runeCount < 12 {
		return ErrPasswordTooShort
	}
	if runeCount > 128 {
		return ErrPasswordTooLong
	}
	if len(pw) > 512 {
		return ErrPasswordTooLong
	}
	var hasUpper, hasLower, hasDigit, hasSymbol bool
	var prev rune = -1
	repeat := 1
	for _, r := range pw {
		if unicode.IsControl(r) {
			return ErrPasswordHasControl
		}
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasSymbol = true
		}
		if r == prev {
			repeat++
			if repeat >= 4 {
				return ErrPasswordRepeating
			}
		} else {
			prev = r
			repeat = 1
		}
	}
	if !(hasUpper && hasLower && hasDigit && hasSymbol) {
		return ErrPasswordMissingCls
	}
	if emailLocalPart != "" {
		normLocal := norm.NFKC.String(strings.ToLower(strings.TrimSpace(emailLocalPart)))
		normPW := norm.NFKC.String(strings.ToLower(pw))
		if normPW == normLocal {
			return ErrPasswordEqualsMail
		}
	}
	return nil
}

// LocalPart extrae la parte local de un email normalizado.
func LocalPart(emailNormalized string) string {
	if i := strings.Index(emailNormalized, "@"); i >= 0 {
		return emailNormalized[:i]
	}
	return ""
}
