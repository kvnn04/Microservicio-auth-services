package dto

// SessionsListResponse 200 del inventario propio (contracts.md).
// Sin jti/family/tokens/hashes (solo sid + labels + current).
type SessionsListResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Total    int               `json:"total"`
		Sessions []SessionListItem `json:"sessions"`
	} `json:"data"`
}

// SessionListItem fila pública (location null si sin GeoIP).
type SessionListItem struct {
	SID         string `json:"sid"`
	DeviceLabel string `json:"device_label"`
	IPMasked    string `json:"ip_masked"`
	Location    *string `json:"location"`
	CreatedAt   string `json:"created_at"`
	LastSeenAt  string `json:"last_seen_at"`
	Current     bool   `json:"current"`
}

// RevokeOneResponse 200 del bisturí (actual intacta).
type RevokeOneResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Status string `json:"status"`
		SID    string `json:"sid"`
	} `json:"data"`
}

func NewSessionsListResult(total int, items []SessionListItem) SessionsListResponse {
	r := SessionsListResponse{Success: true}
	r.Data.Total = total
	r.Data.Sessions = items
	if r.Data.Sessions == nil {
		r.Data.Sessions = []SessionListItem{}
	}
	return r
}

func NewRevokeOneResult(sid string) RevokeOneResponse {
	r := RevokeOneResponse{Success: true}
	r.Data.Status = "revoked"
	r.Data.SID = sid
	return r
}

func NewUseLogout() ErrorResponse {
	return NewError("USE_LOGOUT", "Usa POST /logout para esta sesión.", nil)
}

func NewSessionNotFound() ErrorResponse {
	return NewError("SESSION_NOT_FOUND", "Sesión no encontrada.", nil)
}

func NewSessionsValidationFailed() ErrorResponse {
	return NewError("VALIDATION_FAILED", "Datos inválidos.", nil)
}
