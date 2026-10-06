package service

import (
	"auth-identity-service/internal/domain/user"
)

// uniqueness_policy.go (CU-REG-03): helpers transversales anti-enumeración.
// El dominio decide (user.DecideProbe / user.ShouldNotify); aquí solo
// salidas genéricas idénticas para unique y shadow (el handler nunca ve `found`).

// GenericRegisterStatus es el único status expuesto por POST /register.
const GenericRegisterStatus = "pending_verification"

// GenericResendStatus es el único status expuesto por POST /resend-verification.
const GenericResendStatus = "if_exists_verification_sent"

// ProbeAndNotify resuelve el outcome interno de una sonda (testeable sin I/O).
func ProbeAndNotify(found, throttleAllowed bool) user.ProbeOutcome {
	return user.DecideProbe(found, throttleAllowed)
}
