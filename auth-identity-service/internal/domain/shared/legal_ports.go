package shared

import "context"

// TermsOutdatedError porta las versiones activas para meta.active (contrato).
// El servicio la retorna; el handler la mapea a 400 TERMS_OUTDATED.
type TermsOutdatedError struct {
	ActiveTerms   string
	ActivePrivacy string
}

func (e *TermsOutdatedError) Error() string {
	return ErrTermsOutdated.Error() + ": terms=" + e.ActiveTerms + " privacy=" + e.ActivePrivacy
}

func (e *TermsOutdatedError) Unwrap() error { return ErrTermsOutdated }

// LegalVersionProvider puerto de versiones activas (fail-closed en register,
// degradado con stale solo en GET /legal/active).
type LegalVersionProvider interface {
	// GetActive retorna vigentes desde DB (revalida aunque haya cache).
	// ErrLegalInfra si DB+cache caen → register 500 sin crear nada.
	GetActive(ctx context.Context) (terms, privacy LegalDocument, err error)
}

// ConsentLedger puerto del ledger inmutable (append-only).
type ConsentLedger interface {
	// RecordTx inserta recs con ON CONFLICT(user_id,doc_type,version) DO NOTHING.
	// tx es opaca (any) para no importar pgx en dominio; el adapter castea.
	RecordTx(ctx context.Context, tx any, recs []ConsentRecord) error
}
