package dto

// FederatedCallbackResponse éxito federado (contracts.md).
type FederatedCallbackResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Status   string `json:"status"`
		Provider string `json:"provider"`
		Message  string `json:"message"`
	} `json:"data"`
}

func NewFederatedSuccess(status, provider string) FederatedCallbackResponse {
	r := FederatedCallbackResponse{Success: true}
	r.Data.Status = status
	r.Data.Provider = provider
	switch status {
	case "active":
		r.Data.Message = "Sesión iniciada con Google."
	case "pending_verification":
		r.Data.Message = "Verifica tu correo para activar."
	default:
		r.Data.Message = "OK."
	}
	return r
}
