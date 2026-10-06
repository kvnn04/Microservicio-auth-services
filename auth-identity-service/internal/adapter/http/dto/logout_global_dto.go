package dto

// LogoutGlobalResponse 200 del corte total (contracts.md).
// sessions_revoked cuenta las muertas EN ESTE corte (repeat → 0).
type LogoutGlobalResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Status          string `json:"status"`
		SessionsRevoked int    `json:"sessions_revoked"`
	} `json:"data"`
}

func NewLogoutGlobalResult(sessions int) LogoutGlobalResponse {
	r := LogoutGlobalResponse{Success: true}
	r.Data.Status = "logged_out_global"
	r.Data.SessionsRevoked = sessions
	return r
}
