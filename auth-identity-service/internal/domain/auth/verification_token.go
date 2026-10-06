package auth

import (
	"errors"
	"time"
)

const (
	VerificationTTL         = 15 * time.Minute
	VerificationMaxAttempts = 3
)

var (
	ErrTokenExpired     = errors.New("verification token expired")
	ErrTokenConsumed    = errors.New("verification token already consumed")
	ErrTokenMaxAttempts = errors.New("verification token max attempts exceeded")
)

// VerificationToken: solo se persiste su hash SHA-256, nunca el plano.
type VerificationToken struct {
	UserID      string
	TokenHash   string
	ExpiresAt   time.Time
	Attempts    int
	MaxAttempts int
	Consumed    bool
	CreatedAt   time.Time
}

func NewVerificationToken(userID, tokenHash string, now time.Time) *VerificationToken {
	return &VerificationToken{
		UserID: userID, TokenHash: tokenHash,
		ExpiresAt: now.UTC().Add(VerificationTTL),
		Attempts: 0, MaxAttempts: VerificationMaxAttempts,
		Consumed: false, CreatedAt: now.UTC(),
	}
}

func (t *VerificationToken) IsExpired(now time.Time) bool {
	return !now.UTC().Before(t.ExpiresAt)
}

func (t *VerificationToken) CanAttempt(now time.Time) error {
	if t.Consumed {
		return ErrTokenConsumed
	}
	if t.IsExpired(now) {
		return ErrTokenExpired
	}
	if t.Attempts >= t.MaxAttempts {
		return ErrTokenMaxAttempts
	}
	return nil
}
