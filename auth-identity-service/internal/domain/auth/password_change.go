package auth

import (
	"crypto/subtle"
	"time"

	"auth-identity-service/internal/domain/user"
)

// Constantes CU-CRED-02 (Q2/Q5): historial ventana móvil N=5, rate 5/hora.
// La rotación exige la actual (=Step-Up) o token Step-Up si federated-set.
const (
	PasswordHistoryN      = 5
	PwdChangeRatePerHour  = 5
	PwdChangeRateWindow   = time.Hour
)

// ChangeAccount resume lo necesario para rotar (sin exponer secretos fuera
// de la capa que los verifica; el hash solo viaja al verificador Argon2).
type ChangeAccount struct {
	ID        string
	Email     string
	Hash      string // "" si federated-only sin password
	Ver       int
	Status    user.Status
}

// HasPassword indica si exige current_password (equivale a Step-Up).
func (a *ChangeAccount) HasPassword() bool {
	return a != nil && a.Hash != ""
}

// DistinctFromHashes verifica new ∉ ({actual} ∪ historial) con Argon2.
// Retorna (esActual, enHistorial). Un hash corrupto que falla Verify con
// error (no false) se ignora + warn (no bloquea cambio legítimo, §4.2).
func DistinctFromHashes(newPlain string, verify func(plain, hash string) (bool, error), currentHash string, history []string) (reusedActual, inHistory bool, dirty int) {
	if currentHash != "" {
		if ok, err := verify(newPlain, currentHash); err == nil {
			if ok {
				return true, false, 0
			}
		} else {
			dirty++
		}
	}
	for _, h := range history {
		if h == "" {
			continue
		}
		if ok, err := verify(newPlain, h); err == nil {
			if ok {
				return false, true, dirty
			}
		} else {
			dirty++
		}
	}
	return false, false, dirty
}

// SameHash compara hashes en tiempo constante (anti-timing en Tx).
func SameHash(a, b string) bool {
	if len(a) == 0 || len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
