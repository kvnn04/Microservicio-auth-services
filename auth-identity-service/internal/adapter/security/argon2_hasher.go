package security

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// SEC-02 exacto: m=65536 (64MiB), t=3, p=4, salt 16B, out 32B, PHC.
// Son los defaults OWASP; por env se pueden bajar SOLO para dev/test
// (ver ARGON2_* en .env.example). Verify siempre lee params del PHC,
// así que hashes viejos siguen válidos tras cambiar params.
const (
	defaultMemory      uint32 = 65536
	defaultIterations  uint32 = 3
	defaultParallelism uint8  = 4
	saltLen            = 16
	keyLen             uint32 = 32
)

// Pisos de seguridad: valores bajo esto se elevan al piso (un typo en
// env nunca debe debilitar el hash en silencio).
const (
	minMemory      uint32 = 8192
	minIterations  uint32 = 1
	minParallelism uint8  = 1
)

// Argon2Params costo del hash (solo afecta hashes NUEVOS).
type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
}

// DefaultArgon2Params OWASP para producción.
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{Memory: defaultMemory, Iterations: defaultIterations, Parallelism: defaultParallelism}
}

// Argon2Hasher implementa auth.PasswordHasher. Pepper opcional vía env.
type Argon2Hasher struct {
	pepper []byte
	params Argon2Params
}

func NewArgon2Hasher(pepper []byte) *Argon2Hasher {
	return NewArgon2HasherWithParams(pepper, DefaultArgon2Params())
}

// NewArgon2HasherWithParams permite costo por ambiente (dev/test).
// Valores bajo el piso se elevan al piso.
func NewArgon2HasherWithParams(pepper []byte, p Argon2Params) *Argon2Hasher {
	if p.Memory < minMemory {
		p.Memory = minMemory
	}
	if p.Iterations < minIterations {
		p.Iterations = minIterations
	}
	if p.Parallelism < minParallelism {
		p.Parallelism = minParallelism
	}
	return &Argon2Hasher{pepper: pepper, params: p}
}

func (h *Argon2Hasher) Hash(_ context.Context, plain string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("rand salt: %w", err)
	}
	input := plain
	if len(h.pepper) > 0 {
		input = plain + string(h.pepper)
	}
	hash := argon2.IDKey([]byte(input), salt, h.params.Iterations, h.params.Memory, h.params.Parallelism, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.params.Memory, h.params.Iterations, h.params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

func (h *Argon2Hasher) Verify(_ context.Context, plain, encodedHash string) (bool, error) {
	// PHC: $argon2id$v=<n>$m=<m>,t=<t>,p=<p>$<salt>$<hash> (split exacto, sin Sscanf).
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("invalid phc format")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, fmt.Errorf("invalid phc version")
	}
	var mem, iters uint32
	var par uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &iters, &par); err != nil {
		return false, fmt.Errorf("invalid phc params")
	}
	if version <= 0 || mem == 0 || iters == 0 || par == 0 {
		return false, fmt.Errorf("invalid phc params")
	}
	salt, err := b64DecodeAny(parts[4])
	if err != nil {
		return false, fmt.Errorf("invalid salt: %w", err)
	}
	expected, err := b64DecodeAny(parts[5])
	if err != nil {
		return false, fmt.Errorf("invalid hash: %w", err)
	}
	input := plain
	if len(h.pepper) > 0 {
		input = plain + string(h.pepper)
	}
	actual := argon2.IDKey([]byte(input), salt, iters, mem, par, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

// b64DecodeAny acepta RawStd (canónico) y Std (compat filas legacy).
func b64DecodeAny(s string) ([]byte, error) {
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// HashTokenSHA256 helper (tokens verificación).
func HashTokenSHA256(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}
