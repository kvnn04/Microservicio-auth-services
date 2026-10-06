package auth

import "context"

// BackupCodeIssuer genera pares (plano, hash) con pepper+rotación.
type BackupCodeIssuer interface {
	// Generate retorna plano canónico + hash persistible (único en memoria).
	Generate(ctx context.Context) (plain, hash string, err error)
	// Hash determinista con pepper actual (para lookup por índice).
	Hash(canonical string) string
	// HashPrev con pepper previo (rotación); ok=false si no hay previo.
	HashPrev(canonical string) (string, bool)
	// Verify compara ConstantTime probando actual y previo (rotación).
	Verify(ctx context.Context, canonical, storedHash string) bool
}

// BackupCodeStore ciclo de vida en PG (single-use irreversible, RN-02).
type BackupCodeStore interface {
	// GenerateTx quema previos si supersede + inserta hashes (rellena hasta 10).
	// Retorna superseded (previos invalidados) para el evento.
	GenerateTx(ctx context.Context, userID string, hashes []string, supersede bool) (superseded int, err error)
	// ConsumeTx SELECT FOR UPDATE + quema + remaining + outbox, todo en Tx.
	// Miss/used → ErrBackupNotFound|ErrBackupUsed (servicio mapea a 401 opaco).
	ConsumeTx(ctx context.Context, userID, hash, challengeID string) (remaining int, err error)
	// CountRemaining cuenta used=false (status + warnings).
	CountRemaining(ctx context.Context, userID string) (int, error)
	// BurnAll marca used+superseded (disable MFA).
	BurnAll(ctx context.Context, userID string) error
}
