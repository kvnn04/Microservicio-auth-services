package dto

// RegisterRequest payload POST /api/v1/auth/register (contracts.md).
type RegisterRequest struct {
	Email          string `json:"email"`
	Password       string `json:"password"`
	TermsAccepted  bool   `json:"terms_accepted"`
	TermsVersion   string `json:"terms_version"`
	PrivacyVersion string `json:"privacy_version"`
}

// RegisterResponse éxito Y duplicado-shadow idénticos. Nunca user_id/email/token.
type RegisterResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	} `json:"data"`
}

type ErrorDetail struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

type ErrorResponse struct {
	Success bool `json:"success"`
	Error   struct {
		Code    string        `json:"code"`
		Message string        `json:"message"`
		Details []ErrorDetail `json:"details"`
	} `json:"error"`
}

func NewRegisterSuccess() RegisterResponse {
	r := RegisterResponse{Success: true}
	r.Data.Status = "pending_verification"
	r.Data.Message = "Si el email es válido recibirás instrucciones para verificar tu cuenta."
	return r
}

func NewError(code, message string, details []ErrorDetail) ErrorResponse {
	e := ErrorResponse{Success: false}
	e.Error.Code = code
	e.Error.Message = message
	e.Error.Details = details
	if e.Error.Details == nil {
		e.Error.Details = []ErrorDetail{}
	}
	return e
}

// ErrorResponseWithMeta extiende el error con meta (solo versiones públicas).
type ErrorResponseWithMeta struct {
	Success bool `json:"success"`
	Error   struct {
		Code    string        `json:"code"`
		Message string        `json:"message"`
		Details []ErrorDetail `json:"details"`
	} `json:"error"`
	Meta map[string]any `json:"meta,omitempty"`
}

// NewTermsOutdated construye el 400 TERMS_OUTDATED + meta.active (contrato).
func NewTermsOutdated(field, activeTerms, activePrivacy string) ErrorResponseWithMeta {
	r := ErrorResponseWithMeta{Success: false}
	r.Error.Code = "TERMS_OUTDATED"
	r.Error.Message = "Aceptaste una versión desactualizada. Revisa la vigente."
	r.Error.Details = []ErrorDetail{{Field: field, Reason: "OUTDATED"}}
	r.Meta = map[string]any{
		"active": map[string]string{"terms": activeTerms, "privacy": activePrivacy},
	}
	return r
}
