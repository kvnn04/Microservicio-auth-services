package dto

// LoginRequest payload POST /api/v1/auth/login (contracts.md).
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginSuccessResponse 200 sin MFA (cookies aparte, sin user_id/email).
type LoginSuccessResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	} `json:"data"`
}

// MFARequiredResponse 202 con pre-token aislado (solo /mfa/verify).
type MFARequiredResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Status    string   `json:"status"`
		MFAToken  string   `json:"mfa_token"`
		Methods   []string `json:"methods"`
		ExpiresIn int      `json:"expires_in"`
	} `json:"data"`
}

func NewLoginSuccess() LoginSuccessResponse {
	r := LoginSuccessResponse{Success: true}
	r.Data.Status = "active"
	r.Data.Message = "Sesión iniciada."
	return r
}

func NewMFARequired(token string, expiresIn int) MFARequiredResponse {
	r := MFARequiredResponse{Success: true}
	r.Data.Status = "mfa_required"
	r.Data.MFAToken = token
	r.Data.Methods = []string{"totp"}
	r.Data.ExpiresIn = expiresIn
	return r
}

func NewInvalidCredentials() ErrorResponse {
	return NewError("INVALID_CREDENTIALS", "Credenciales incorrectas.", nil)
}
