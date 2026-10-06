package errors

import (
	"errors"
	"net/http"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/user"
	"auth-identity-service/internal/service"
)

// MapDomainError traduce dominio a HTTP sin fugar trazas. Nunca 409 en CU-REG-01.
func MapDomainError(err error) (status int, code string) {
	var ve *service.ValidationError
	if errors.As(err, &ve) || errors.Is(err, auth.ErrValidation) ||
		errors.Is(err, user.ErrInvalidEmail) || errors.Is(err, user.ErrEmailTooLong) {
		return http.StatusBadRequest, "VALIDATION_FAILED"
	}
	if errors.Is(err, auth.ErrRateLimited) {
		return http.StatusTooManyRequests, "RATE_LIMITED"
	}
	if errors.Is(err, auth.ErrInvalidCredentials) {
		return http.StatusUnauthorized, "INVALID_CREDENTIALS"
	}
	if errors.Is(err, auth.ErrInvalidOrExpired) ||
		errors.Is(err, auth.ErrPlessInvalid) || errors.Is(err, auth.ErrPlessBurned) ||
		errors.Is(err, auth.ErrPwdResetInvalid) || errors.Is(err, auth.ErrPwdResetBurned) ||
		errors.Is(err, user.ErrEmailChangeInvalid) || errors.Is(err, user.ErrEmailChangeBurned) {
		return http.StatusBadRequest, "INVALID_OR_EXPIRED"
	}
	if errors.Is(err, user.ErrEmailAlreadyInUse) {
		return http.StatusConflict, "EMAIL_TAKEN"
	}
	if errors.Is(err, auth.ErrUnknownScope) {
		return http.StatusBadRequest, "UNKNOWN_SCOPE"
	}
	if errors.Is(err, auth.ErrPasswordReused) {
		return http.StatusBadRequest, "PASSWORD_REUSED"
	}
	if errors.Is(err, auth.ErrStepUpRequired) {
		return http.StatusUnauthorized, "STEP_UP_REQUIRED"
	}
	if errors.Is(err, auth.ErrStepUpReused) {
		return http.StatusUnauthorized, "STEP_UP_REUSED"
	}
	if errors.Is(err, auth.ErrStepUpInvalid) {
		return http.StatusUnauthorized, "INVALID_STEP_UP"
	}
	if errors.Is(err, auth.ErrStepUpRelogin) {
		return http.StatusUnauthorized, "STEP_UP_REQUIRES_RELOGIN"
	}
	if errors.Is(err, auth.ErrStepUpUnavailable) {
		return http.StatusInternalServerError, "STEP_UP_UNAVAILABLE"
	}
	if errors.Is(err, user.ErrDuplicateShadow) || errors.Is(err, auth.ErrDuplicateShadow) {
		return http.StatusCreated, "PENDING"
	}
	return http.StatusInternalServerError, "INTERNAL_ERROR"
}
