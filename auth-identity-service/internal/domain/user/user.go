package user

import (
	"errors"
	"time"
)

// Status representa el ciclo de vida de una identidad.
// Solo ACTIVE puede autenticarse (RN-01).
type Status string

const (
	StatusPendingVerification Status = "PENDING_VERIFICATION"
	StatusActive              Status = "ACTIVE"
	StatusLocked              Status = "LOCKED"
	StatusSoftDeleted         Status = "SOFT_DELETED"
)

// Errores de dominio (sentinel) del subdominio user.
var (
	ErrInvalidEmail        = errors.New("invalid email")
	ErrEmailTooLong        = errors.New("email exceeds 254 characters")
	ErrInvalidUserState    = errors.New("invalid user state")
	ErrMissingTerms        = errors.New("terms acceptance is required")
	ErrMissingPasswordHash = errors.New("password hash is required")
	ErrUserNotFound        = errors.New("user not found")
	ErrEmailAlreadyInUse   = errors.New("email already in use")
	ErrNotFound            = errors.New("user not found")
	ErrAlreadyExists       = errors.New("user already exists")
	ErrDuplicateShadow     = errors.New("duplicate shadow: email already registered")
	ErrAlreadyLinked       = errors.New("federated identity already linked")
	ErrEmailCollision      = errors.New("email already registered with different credential")
)

// User es la entidad raíz del subdominio user.
// Código puro: sin imports de infra, frameworks ni drivers.
type User struct {
	ID              string
	EmailNormalized string
	EmailOriginal   string
	PasswordHash    string // "" + PasswordAlgo "federated" si federated_only
	PasswordAlgo    string
	Status          Status
	TermsVersion    string
	PrivacyVersion  string
	TermsAcceptedAt time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
	FederatedOnly   bool   // CU-REG-04: sin password local
	TermsSource     string // "classic" | "federated_google" (CU-REG-04 RN-05)
	MFAEnabled      bool   // CU-AUTH-01: bifurca a desafío MFA (gestiona CU-AUTH-02)
}

// NewUser crea una identidad en estado PENDING_VERIFICATION.
func NewUser(id, emailOriginal, emailNormalized, passwordHash, termsVersion, privacyVersion string, now time.Time) (*User, error) {
	if emailNormalized == "" {
		return nil, ErrInvalidEmail
	}
	if len(emailNormalized) > 254 {
		return nil, ErrEmailTooLong
	}
	if passwordHash == "" {
		return nil, ErrMissingPasswordHash
	}
	if termsVersion == "" || privacyVersion == "" {
		return nil, ErrMissingTerms
	}
	if id == "" {
		return nil, ErrInvalidUserState
	}
	return &User{
		ID:              id,
		EmailOriginal:   emailOriginal,
		EmailNormalized: emailNormalized,
		PasswordHash:    passwordHash,
		PasswordAlgo:    "argon2id",
		Status:          StatusPendingVerification,
		TermsVersion:    termsVersion,
		PrivacyVersion:  privacyVersion,
		TermsAcceptedAt: now.UTC(),
		CreatedAt:       now.UTC(),
		UpdatedAt:       now.UTC(),
		TermsSource:     "classic",
	}, nil
}

// CanAuthenticate solo retorna true si la cuenta está ACTIVA.
func (u *User) CanAuthenticate() bool {
	return u != nil && u.Status == StatusActive
}

// Activate transiciona PENDING_VERIFICATION → ACTIVE (CU-REG-02 RN-01).
// Cualquier otro estado retorna error (LOCKED/SOFT_DELETED nunca se activan
// por verify; ACTIVE repetido solo vía idempotencia already_verified del adapter).
func (u *User) Activate(now time.Time) error {
	if u == nil || u.Status != StatusPendingVerification {
		return ErrInvalidUserState
	}
	u.Status = StatusActive
	u.UpdatedAt = now.UTC()
	return nil
}

// NewFederatedUser crea identidad sin password local (CU-REG-04).
// Status inicial según email_verified del IdP: verified→ACTIVE, si no PENDING.
func NewFederatedUser(id, emailOriginal, emailNormalized, termsVersion, privacyVersion, source string, verified bool, now time.Time) (*User, error) {
	if emailNormalized == "" {
		return nil, ErrInvalidEmail
	}
	if len(emailNormalized) > 254 {
		return nil, ErrEmailTooLong
	}
	if termsVersion == "" || privacyVersion == "" {
		return nil, ErrMissingTerms
	}
	if id == "" {
		return nil, ErrInvalidUserState
	}
	status := StatusPendingVerification
	if verified {
		status = StatusActive
	}
	return &User{
		ID:              id,
		EmailOriginal:   emailOriginal,
		EmailNormalized: emailNormalized,
		PasswordHash:    "",
		PasswordAlgo:    "federated",
		Status:          status,
		TermsVersion:    termsVersion,
		PrivacyVersion:  privacyVersion,
		TermsAcceptedAt: now.UTC(),
		CreatedAt:       now.UTC(),
		UpdatedAt:       now.UTC(),
		FederatedOnly:   true,
		TermsSource:     source,
	}, nil
}
