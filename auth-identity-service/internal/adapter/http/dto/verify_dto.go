package dto

// VerifyRequest: exactamente uno de token|code (contracts.md).
type VerifyRequest struct {
	Token *string `json:"token,omitempty"`
	Code  *string `json:"code,omitempty"`
}

// VerifyResponse 200 active / already_verified.
type VerifyResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	} `json:"data"`
}

// ResendRequest reenvío (respuesta siempre genérica 202).
type ResendRequest struct {
	Email string `json:"email"`
}

// ResendResponse 202 genérico anti-enumeración.
type ResendResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	} `json:"data"`
}

func NewVerifySuccess(status string) VerifyResponse {
	r := VerifyResponse{Success: true}
	r.Data.Status = status
	if status == "already_verified" {
		r.Data.Message = "Esta cuenta ya estaba verificada."
	} else {
		r.Data.Message = "Cuenta verificada. Ya puedes iniciar sesión."
	}
	return r
}

func NewInvalidOrExpired() ErrorResponse {
	return NewError("INVALID_OR_EXPIRED",
		"El enlace o código es inválido o expiró. Solicita uno nuevo.", nil)
}

func NewResendQueued() ResendResponse {
	r := ResendResponse{Success: true}
	r.Data.Status = "if_exists_verification_sent"
	r.Data.Message = "Si la cuenta existe y está pendiente, recibirás un nuevo correo."
	return r
}
