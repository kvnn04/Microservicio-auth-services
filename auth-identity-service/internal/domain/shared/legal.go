package shared

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Documentos MVP (RN-01): terms, privacy exactos lowercase.
type DocType string

const (
	DocTerms   DocType = "terms"
	DocPrivacy DocType = "privacy"
)

var (
	ErrTermsRequired = errors.New("terms acceptance required")
	ErrTermsOutdated = errors.New("terms version outdated")
	ErrInvalidFormat = errors.New("invalid legal format")
	ErrLegalInfra    = errors.New("legal store unavailable")
)

var versionRegex = regexp.MustCompile(`^v\d{4}\.\d{2}$`)

// LegalDocument versión versionada de un documento legal (RN-02).
type LegalDocument struct {
	DocType       DocType
	Version       string
	ContentHash   string
	URL           string
	EffectiveFrom time.Time
	IsActive      bool
}

// ValidateFormat exige ^vYYYY.MM (hash/url se validan en seed, no en request).
func (d LegalDocument) ValidateFormat() error {
	if d.DocType != DocTerms && d.DocType != DocPrivacy {
		return fmt.Errorf("doc_type: %w", ErrInvalidFormat)
	}
	if !versionRegex.MatchString(d.Version) {
		return fmt.Errorf("version: %w", ErrInvalidFormat)
	}
	return nil
}

// ConsentRecord fila inmutable del ledger (RN-03: append-only, sin UPDATE/DELETE).
type ConsentRecord struct {
	ID         string
	UserID     string
	DocType    DocType
	Version    string
	AcceptedAt time.Time
	IPHash     string
	UAHash     string
	Source     string
	RequestID  string
}

// NewConsentRecord valida doc/version no vacíos con formato.
func NewConsentRecord(userID string, doc DocType, version, ipHash, uaHash, source, requestID string) (*ConsentRecord, error) {
	if userID == "" || ipHash == "" || source == "" || requestID == "" {
		return nil, fmt.Errorf("consent attribution: %w", ErrInvalidFormat)
	}
	if err := (LegalDocument{DocType: doc, Version: version}).ValidateFormat(); err != nil {
		return nil, err
	}
	return &ConsentRecord{
		UserID: userID, DocType: doc, Version: version,
		AcceptedAt: time.Now().UTC(),
		IPHash: ipHash, UAHash: uaHash, Source: source, RequestID: requestID,
	}, nil
}

// ValidateConsentInput chequeo previo a DB (RN-04): bool estricto + formatos.
func ValidateConsentInput(accepted bool, termsVer, privVer string) error {
	if !accepted {
		return ErrTermsRequired
	}
	if !versionRegex.MatchString(termsVer) || !versionRegex.MatchString(privVer) {
		return fmt.Errorf("terms_version: %w", ErrInvalidFormat)
	}
	return nil
}
