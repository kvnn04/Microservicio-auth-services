package dto

// LogoutRequest body alternativo POST /logout (contracts.md).
// Sin Bearer, acepta {refresh_token} para localizar family→sid.
// Body ≤4KB, resto se ignora (sin 400 por campos extra).
type LogoutRequest struct {
	RefreshToken *string `json:"refresh_token,omitempty"`
}

// LogoutResponse 200 (ambos): logged_out o already_logged_out.
type LogoutResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Status string `json:"status"`
	} `json:"data"`
}

func NewLogoutResult(status string) LogoutResponse {
	r := LogoutResponse{Success: true}
	r.Data.Status = status
	return r
}

func NewLogoutUnauthorized() ErrorResponse {
	return NewError("UNAUTHORIZED", "No autenticado.", nil)
}

func NewLogoutRateLimited() ErrorResponse {
	return NewError("RATE_LIMITED", "Demasiadas solicitudes. Intenta de nuevo en unos segundos.", nil)
}
