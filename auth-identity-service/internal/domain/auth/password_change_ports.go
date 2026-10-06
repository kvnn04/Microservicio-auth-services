package auth

import (
	"context"
	"errors"
)

var (
	// ErrInvalidCurrent: current errónea → 401 + RecordFail a lock cuenta.
	ErrInvalidCurrent = errors.New("current password is incorrect")
	// ErrPasswordInHistory: new ∈ últimos 5 → 400 con meta {n:5}.
	ErrPasswordInHistory = errors.New("new password is in recent history")
	// ErrMissingCurrent: current ausente cuando se exige → 400 programático.
	ErrMissingCurrent = errors.New("current password is required")
	// ErrUnexpectedCurrent: current enviado en federated-set → 400.
	ErrUnexpectedCurrent = errors.New("current password must not be sent without local password")
)

// PasswordHistoryStore puerto de persistencia (CU-CRED-02 Q2/Q7).
// Append-only (sin UNIQUE que bloquee re-uso tras ventana, RN-02).
type PasswordHistoryStore interface {
	// Current resuelve cuenta para rotar (hash+ver+status+email).
	Current(ctx context.Context, userID string) (*ChangeAccount, error)
	// LastN últimos N hashes (desc). Falla Verify corrupto → se ignora.
	LastN(ctx context.Context, userID string, n int) ([]string, error)
	// RotateTx rota en Tx atómica: re-chequea base (TOCTOU optimista por
	// password_ver) + INSERT history(old) + UPDATE users(new,ver+1) +
	// revoke families/sessions salvo keep + outbox + email.
	// Base movida → ErrPasswordReused; usuario ido → ErrPasswordReused opaco.
	RotateTx(ctx context.Context, userID, oldHash, newHash string, expectedVer int, keepSID, requestID string) (newVer, peersRevoked int, err error)
}
