package auth

import "context"

// PasswordHasher puerto criptográfico (Argon2id SEC-02).
type PasswordHasher interface {
	Hash(ctx context.Context, plain string) (string, error)
	Verify(ctx context.Context, plain, encodedHash string) (bool, error)
}

// BreachChecker verifica corpus filtrado (HIBP k-anonymity, timeout 800ms).
type BreachChecker interface {
	IsCompromised(ctx context.Context, password string) (bool, error)
}

// VerificationTokenIssuer genera tokens opacos 32B y su hash SHA-256.
type VerificationTokenIssuer interface {
	Generate() (plainToken string, tokenHash string, err error)
	HashToken(plain string) string
}
