package service

import (
	"errors"

	"auth-identity-service/internal/domain/shared"
)

// legal_consent.go (CU-REG-05): helpers puros transversales.
// El dominio decide formatos (shared.ValidateConsentInput); aquí el match
// exacto contra activas + construcción de atribución para la Tx.

// ConsentMetricsPort telemetría CU-REG-05 (inyectable, nil-safe vía Noop).
type ConsentMetricsPort interface {
	IncConsentRecorded(docType, source string)
	IncConsentRejected(reason string)
	IncConsentOutdated(docType string)
}

// NoopConsentMetrics default sin telemetría (tests).
type NoopConsentMetrics struct{}

func (NoopConsentMetrics) IncConsentRecorded(string, string) {}
func (NoopConsentMetrics) IncConsentRejected(string)         {}
func (NoopConsentMetrics) IncConsentOutdated(string)         {}

// CheckConsentFast valida accepted+formatos sin I/O (antes de Probe).
// Retorna ValidationError-es de dominio para mapeo 400 del handler.
func CheckConsentFast(accepted bool, termsVer, privVer string) error {
	if err := shared.ValidateConsentInput(accepted, termsVer, privVer); err != nil {
		return err
	}
	return nil
}

// CheckConsentAgainstActive exige match EXACTO con activas DB.
// Mismatch → *TermsOutdatedError (400 TERMS_OUTDATED + meta.active).
func CheckConsentAgainstActive(termsVer, privVer string, activeT, activeP shared.LegalDocument) error {
	if termsVer != activeT.Version || privVer != activeP.Version {
		return &shared.TermsOutdatedError{ActiveTerms: activeT.Version, ActivePrivacy: activeP.Version}
	}
	return nil
}

// ConsentValidationError traduce error de dominio a ValidationError HTTP.
func ConsentValidationError(err error) *ValidationError {
	if errors.Is(err, shared.ErrTermsRequired) {
		return &ValidationError{Fields: []FieldError{{Field: "terms_accepted", Reason: "REQUIRED"}}}
	}
	return &ValidationError{Fields: []FieldError{{Field: "terms_version", Reason: "INVALID_FORMAT"}}}
}

// consentMetrics resuelve nil-safe.
func consentMetrics(m ConsentMetricsPort) ConsentMetricsPort {
	if m == nil {
		return NoopConsentMetrics{}
	}
	return m
}
