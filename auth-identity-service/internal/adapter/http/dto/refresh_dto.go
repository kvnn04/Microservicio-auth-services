package dto

// RefreshRequest body alternativo (nativo sin cookies).
type RefreshRequest struct {
	RefreshToken *string `json:"refresh_token,omitempty"`
}

// RefreshResponse 200 (rotate o grace-idempotente: mismo shape, mismo par).
type RefreshResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Status       string `json:"status"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token,omitempty"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		SID          string `json:"sid"`
	} `json:"data"`
}

// NewRefreshResult arma la respuesta (isNative: refresh en body para
// keystore; web: solo cookie + Access en body).
func NewRefreshResult(access, refresh, sid string, expiresIn int, isNative bool) RefreshResponse {
	r := RefreshResponse{Success: true}
	r.Data.Status = "rotated"
	r.Data.AccessToken = access
	r.Data.TokenType = "Bearer"
	r.Data.ExpiresIn = expiresIn
	r.Data.SID = sid
	if isNative {
		r.Data.RefreshToken = refresh
	}
	return r
}

func NewInvalidRefresh() ErrorResponse {
	return NewError("INVALID_REFRESH", "Sesión inválida.", nil)
}

func NewSessionExpired() ErrorResponse {
	return NewError("SESSION_EXPIRED", "Sesión expirada. Inicia sesión de nuevo.", nil)
}

func NewFamilyRevoked() ErrorResponse {
	return NewError("FAMILY_REVOKED", "Sesión cerrada. Inicia sesión de nuevo.", nil)
}

func NewSessionCompromised() ErrorResponse {
	return NewError("SESSION_COMPROMISED", "Detectamos uso indebido. Cerramos todo por seguridad.", nil)
}

func NewConcurrentRotation() ErrorResponseWithMeta {
	r := ErrorResponseWithMeta{Success: false}
	r.Error.Code = "CONCURRENT_ROTATION"
	r.Error.Message = "Reintenta con el nuevo token."
	r.Error.Details = []ErrorDetail{}
	r.Meta = map[string]any{"retry": true, "retry_after_ms": 200}
	return r
}
