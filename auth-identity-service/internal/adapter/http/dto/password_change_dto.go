package dto

// ChangePasswordRequest entrada POST /password/change (contracts.md).
// current_password obligatorio si hay hash local; prohibido en federated-set.
type ChangePasswordRequest struct {
	CurrentPassword *string `json:"current_password,omitempty"`
	NewPassword     string  `json:"new_password"`
}

// ChangePasswordResponse 200 cambio aplicado (sesión actual intacta).
type ChangePasswordResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Status          string `json:"status"`
		Message         string `json:"message"`
		SessionsRevoked int    `json:"sessions_revoked"`
	} `json:"data"`
}

func NewPasswordChangedResult(revoked int) ChangePasswordResponse {
	r := ChangePasswordResponse{Success: true}
	r.Data.Status = "password_changed"
	r.Data.Message = "Inicia sesión con tu nueva clave."
	r.Data.SessionsRevoked = revoked
	return r
}

func NewInvalidCurrent() ErrorResponse {
	return NewError("INVALID_CURRENT", "La clave actual no es correcta.", nil)
}

func NewPasswordInHistory() ErrorResponseWithMeta {
	r := ErrorResponseWithMeta{Success: false}
	r.Error.Code = "PASSWORD_IN_HISTORY"
	r.Error.Message = "Ya usaste esa clave recientemente."
	r.Error.Details = []ErrorDetail{}
	r.Meta = map[string]any{"n": 5}
	return r
}

func NewMissingCurrent() ErrorResponse {
	return NewError("MISSING_CURRENT", "Indica tu clave actual.", nil)
}

func NewUnexpectedCurrent() ErrorResponse {
	return NewError("UNEXPECTED_CURRENT", "Tu cuenta no tiene clave local.", nil)
}
