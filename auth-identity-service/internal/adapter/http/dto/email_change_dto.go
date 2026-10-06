package dto

// EmailChangeStartRequest entrada POST /email/change/start (contracts.md).
type EmailChangeStartRequest struct {
	NewEmail string `json:"new_email"`
}

// EmailChangeStartResponse 202 solicitud creada (link al nuevo + aviso al viejo).
type EmailChangeStartResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Status         string `json:"status"`
		NewEmailMasked string `json:"new_email_masked"`
	} `json:"data"`
}

// EmailChangeConfirmRequest entrada POST /email/change/confirm.
type EmailChangeConfirmRequest struct {
	Token string `json:"token"`
}

// EmailChangeConfirmResponse 200 cambio aplicado (sin sesión: re-login).
type EmailChangeConfirmResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Status         string `json:"status"`
		NewEmailMasked string `json:"new_email_masked"`
	} `json:"data"`
}

func NewEmailChangeSent(masked string) EmailChangeStartResponse {
	r := EmailChangeStartResponse{Success: true}
	r.Data.Status = "confirmation_sent"
	r.Data.NewEmailMasked = masked
	return r
}

func NewEmailChanged(masked string) EmailChangeConfirmResponse {
	r := EmailChangeConfirmResponse{Success: true}
	r.Data.Status = "email_changed"
	r.Data.NewEmailMasked = masked
	return r
}

func NewEmailTaken() ErrorResponse {
	return NewError("EMAIL_TAKEN", "Ese correo ya está en uso.", nil)
}

func NewEmailChangeInvalidOrExpired() ErrorResponse {
	return NewError("INVALID_OR_EXPIRED",
		"El enlace es inválido o expiró.", nil)
}

func NewSameEmail() ErrorResponse {
	return NewError("SAME_EMAIL", "El correo es igual al actual.", nil)
}

func NewEmailSendThrottled() ErrorResponse {
	return NewError("EMAIL_SEND_THROTTLED",
		"Demasiadas solicitudes. Intenta de nuevo más tarde.", nil)
}
