package user

import (
	"errors"
	"strings"
	"time"
	"unicode"
)

// Provider de identidad federada (RN-01: MVP solo google, extensible por spec delta).
type Provider string

const (
	ProviderGoogle Provider = "google"
)

var ErrInvalidProvider = errors.New("unsupported identity provider")

// IsSupported indica si el provider está habilitado (MVP: google).
func (p Provider) IsSupported() bool {
	return p == ProviderGoogle
}

// FederatedIdentity vincula un `sub` de IdP con un usuario local.
// Unicidad doble (RN-03): UNIQUE(provider, sub) + UNIQUE(email_normalized).
type FederatedIdentity struct {
	Provider    Provider
	Sub         string
	UserID      string
	EmailAtLink string
	Iss         string
	CreatedAt   time.Time
}

// NewFederatedIdentity valida sub (1..255, sin control) y provider soportado.
func NewFederatedIdentity(p Provider, sub, userID, email string) (*FederatedIdentity, error) {
	if !p.IsSupported() {
		return nil, ErrInvalidProvider
	}
	if len(sub) < 1 || len(sub) > 255 {
		return nil, errors.New("invalid sub length")
	}
	for _, r := range sub {
		if r == 0 || unicode.IsControl(r) {
			return nil, errors.New("invalid sub characters")
		}
	}
	if userID == "" {
		return nil, ErrInvalidUserState
	}
	if strings.TrimSpace(email) == "" {
		return nil, ErrInvalidEmail
	}
	return &FederatedIdentity{
		Provider: p, Sub: sub, UserID: userID,
		EmailAtLink: email, CreatedAt: time.Now().UTC(),
	}, nil
}
