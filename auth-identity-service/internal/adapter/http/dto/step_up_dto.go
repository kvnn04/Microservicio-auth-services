package dto

// StepUpChallengeRequest entrada POST /step-up/challenge (contracts.md).
// password exigido si password_hash existe; code si mfa_enabled.
type StepUpChallengeRequest struct {
	Scope    string  `json:"scope"`
	Password *string `json:"password,omitempty"`
	Code     *string `json:"code,omitempty"`
}

// StepUpChallengeResponse 200 con token scopeado de un uso.
type StepUpChallengeResponse struct {
	Success bool `json:"success"`
	Data    struct {
		StepUpToken string `json:"step_up_token"`
		Scope       string `json:"scope"`
		ExpiresIn   int    `json:"expires_in"`
	} `json:"data"`
}

func NewStepUpChallenge(token, scope string, expiresIn int) StepUpChallengeResponse {
	r := StepUpChallengeResponse{Success: true}
	r.Data.StepUpToken = token
	r.Data.Scope = scope
	r.Data.ExpiresIn = expiresIn
	return r
}

func NewInvalidStepUp() ErrorResponse {
	return NewError("INVALID_STEP_UP", "No pudimos confirmarte.", nil)
}

func NewStepUpReused() ErrorResponse {
	return NewError("STEP_UP_REUSED", "Ese comprobante ya fue usado. Solicita uno nuevo.", nil)
}

func NewStepUpRelogin() ErrorResponse {
	return NewError("STEP_UP_REQUIRES_RELOGIN", "Vuelve a iniciar sesión para continuar.", nil)
}

func NewStepUpRequired(scope string) ErrorResponse {
	return NewError("STEP_UP_REQUIRED", "Confirma tu identidad para continuar.", nil)
}

func NewStepUpUnavailable() ErrorResponse {
	return NewError("STEP_UP_UNAVAILABLE", "No pudimos confirmarte ahora. Intenta de nuevo.", nil)
}
