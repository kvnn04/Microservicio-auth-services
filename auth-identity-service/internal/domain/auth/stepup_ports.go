package auth

import (
	"context"
	"errors"
)

var (
	// ErrUnknownScope: scope ausente o fuera de la lista cerrada → 400.
	ErrUnknownScope = errors.New("unknown step-up scope")
	// ErrStepUpRequired: stale sin token → 401 + meta {scope,max_age}.
	ErrStepUpRequired = errors.New("step-up required")
	// ErrStepUpInvalid: factor malo, token expirado o scope/sub mismatch → 401.
	ErrStepUpInvalid = errors.New("invalid step-up proof")
	// ErrStepUpReused: jti ya quemado → 401 con código distinto (auditoría).
	ErrStepUpReused = errors.New("step-up token already used")
	// ErrStepUpRelogin: federated-only stale sin factores locales → 401
	// con código distinto (único caso sin token posible).
	ErrStepUpRelogin = errors.New("step-up requires fresh re-login")
	// ErrStepUpUnavailable: Redis down (fail-closed) o sin clave → 500.
	ErrStepUpUnavailable = errors.New("step-up temporarily unavailable")
)

// StepUpTokenIssuer firma/verifica step_up_token (Ed25519, aud=step-up).
// Sin I/O: el single-use (jti) vive en StepUpJTIStore.
type StepUpTokenIssuer interface {
	// IssueToken firma {sub, jti UUIDv7, aud:step-up, scope, exp:+300s}.
	IssueToken(ctx context.Context, userID string, scope StepUpScope, amr []string) (token, jti string, err error)
	// VerifyToken valida firma + alg + kid + iss/aud/exp + TTL exacto.
	VerifyToken(token string) (StepUpClaims, error)
}

// StepUpJTIStore single-use de jti (Redis EX 300, GET+DEL atómico).
// Fail-closed: cualquier error de infra → el servicio responde 500
// (el fast-pass offline con JWT sigue funcionando sin Redis).
type StepUpJTIStore interface {
	// Save registra jti virgen (NX). Error → Unavailable.
	Save(ctx context.Context, jti, sub, scope string) error
	// Consume quema atómicamente. found=false → ya usado (Reused).
	Consume(ctx context.Context, jti string) (sub, scope string, found bool, err error)
}
