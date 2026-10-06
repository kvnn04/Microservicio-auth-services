package dto

// PwdResetStartRequest entrada POST /password/reset/start (contracts.md).
type PwdResetStartRequest struct {
	Email string `json:"email"`
}

// PwdResetStartResponse 202 genérico anti-enumeración (siempre igual).
type PwdResetStartResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	} `json:"data"`
}

// PwdResetConfirmRequest entrada POST /password/reset/confirm.
// new_password_confirm opcional: si viene debe coincidir.
type PwdResetConfirmRequest struct {
	Token              string  `json:"token"`
	NewPassword        string  `json:"new_password"`
	NewPasswordConfirm *string `json:"new_password_confirm,omitempty"`
}

// PwdResetConfirmResponse 200 cambio aplicado (sin auto-login).
type PwdResetConfirmResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	} `json:"data"`
}

func NewPwdResetSent() PwdResetStartResponse {
	r := PwdResetStartResponse{Success: true}
	r.Data.Status = "if_exists_sent"
	r.Data.Message = "Si la cuenta existe recibirás un correo."
	return r
}

func NewPasswordChanged() PwdResetConfirmResponse {
	r := PwdResetConfirmResponse{Success: true}
	r.Data.Status = "password_changed"
	r.Data.Message = "Inicia sesión con tu nueva clave."
	return r
}

func NewPwdResetInvalidOrExpired() ErrorResponse {
	return NewError("INVALID_OR_EXPIRED",
		"El enlace es inválido o expiró.", nil)
}

func NewPasswordReused() ErrorResponse {
	return NewError("PASSWORD_REUSED",
		"Elige una clave distinta a la actual.", nil)
}
