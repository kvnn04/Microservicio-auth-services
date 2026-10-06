package dto

// MFA DTOs (contracts.md CU-AUTH-02).

// MFASetupResponse 200 con secreto (UNA vez) + otpauth (front renderiza QR).
type MFASetupResponse struct {
	Success bool `json:"success"`
	Data    struct {
		SecretB32  string `json:"secret_b32"`
		OTPAuthURL string `json:"otpauth_url"`
		ExpiresIn  int    `json:"expires_in"`
	} `json:"data"`
}

// MFAEnableRequest confirmación con código.
type MFAEnableRequest struct {
	Code string `json:"code"`
}

// MFAEnableResponse 200 + backups (UNA vez).
type MFAEnableResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Status      string   `json:"status"`
		BackupCodes []string `json:"backup_codes"`
	} `json:"data"`
}

// MFAVerifyRequest pre-token + código (SIN Bearer).
// code 6d=TOTP o 10ch=backup autodetectado; backup_code alias explícito.
type MFAVerifyRequest struct {
	MFAToken   string `json:"mfa_token"`
	Code       string `json:"code,omitempty"`
	BackupCode string `json:"backup_code,omitempty"`
}

// MFAActiveResponse 200 verify-ok (cookies aparte).
type MFAActiveResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	} `json:"data"`
}

// MFADisabledResponse 200 disable.
type MFADisabledResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Status string `json:"status"`
	} `json:"data"`
}

// MFAStatusResponse estado (sin secreto, con remaining).
type MFAStatusResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Enabled         bool     `json:"enabled"`
		Methods         []string `json:"methods"`
		BackupRemaining int      `json:"backup_remaining"`
		BackupWarning   bool     `json:"backup_warning"`
	} `json:"data"`
}

func NewInvalidMFA() ErrorResponse {
	return NewError("INVALID_MFA", "Código inválido o expirado.", nil)
}
