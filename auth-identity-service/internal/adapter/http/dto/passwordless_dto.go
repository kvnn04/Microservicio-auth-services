package dto

// PlessStartRequest entrada POST /passwordless/start (contracts.md).
type PlessStartRequest struct {
	Email string `json:"email"`
}

// PlessStartResponse 202 genérico anti-enumeración (siempre igual).
type PlessStartResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	} `json:"data"`
}

// PlessVerifyRequest: exactamente uno de token|code (contracts.md).
type PlessVerifyRequest struct {
	Token *string `json:"token,omitempty"`
	Code  *string `json:"code,omitempty"`
}

func NewPlessSent() PlessStartResponse {
	r := PlessStartResponse{Success: true}
	r.Data.Status = "if_exists_sent"
	r.Data.Message = "Si la cuenta existe recibirás un correo."
	return r
}

func NewPlessInvalidOrExpired() ErrorResponse {
	return NewError("INVALID_OR_EXPIRED",
		"El enlace o código es inválido o expiró.", nil)
}
