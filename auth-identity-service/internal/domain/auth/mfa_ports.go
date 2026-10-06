package auth

import (
	"context"
	"errors"
)

var (
	ErrInvalidMFA   = errors.New("invalid mfa code or challenge")
	ErrNoStaged     = errors.New("no staged secret")
	ErrStagedExpired = errors.New("staged secret expired")
	ErrAlreadyEnabled = errors.New("mfa already enabled")
	// ErrReplayUncheckable: reuso indetectable (Redis+DB caídos) → 500
	// explícito en vez de 401 silencioso (único 500 con código distinto).
	ErrReplayUncheckable = errors.New("replay uncheckable")
)

// TOTPProvider puerto cripto TOTP (HMAC-SHA1 RFC4226/6238 en adapter).
type TOTPProvider interface {
	// GenerateSecret 20B CSPRNG + base32 sin padding (una exhibición).
	GenerateSecret(ctx context.Context) (raw []byte, b32 string, err error)
	// CodeAt código para counter (tests/vectores RFC).
	CodeAt(ctx context.Context, raw []byte, counter int64) (string, error)
	// Validate prueba ±1 con ConstantTime; retorna counter coincidente.
	Validate(ctx context.Context, raw []byte, code string, counter int64) (matchedCounter int64, ok bool)
}

// SecretBox cifrado de secretos en reposo (AES-256-GCM, AAD=user_id).
// Constructor fail-fast sin key 32B (el servicio no levanta).
type SecretBox interface {
	Encrypt(ctx context.Context, userID string, raw []byte) (sealed []byte, err error)
	Decrypt(ctx context.Context, userID string, sealed []byte) (raw []byte, err error)
}

// MFASecretStore ciclo de vida del secreto (PG verdad, Redis espejo rápido).
// PromoteTx/DisableTx emiten outbox+mail estándar en la misma Tx (el adapter
// construye eventos deterministas + lookup de email; el servicio no los pasa).
type MFASecretStore interface {
	Stage(ctx context.Context, userID string, secretEnc []byte) error
	Staged(ctx context.Context, userID string) (secretEnc []byte, expired bool, err error)
	PromoteTx(ctx context.Context, userID string) error
	GetActive(ctx context.Context, userID string) (secretEnc []byte, err error)
	DisableTx(ctx context.Context, userID string) error
}

// OutboxEventRef evento mínimo (el adapter lo traduce a su OutboxPayload).
type OutboxEventRef struct {
	EventID   string
	EventType string
	Topic     string
	Payload   []byte
}

// MailRef email transaccional (vacío To = no enviar).
type MailRef struct {
	To      string
	Subject string
	Body    string
}

// MFAChallengeStore single-use + fails + replay (Redis primario, DB fallback).
type MFAChallengeStore interface {
	// Register crea challenge Pendiente (llamado al emitir pre-token en login).
	Register(ctx context.Context, challengeID, userID string) error
	// Consume GET+DEL atómico; miss → ErrNotFound (expirado/quemado).
	Consume(ctx context.Context, challengeID string) (userID string, err error)
	// RecordFail suma fallo; a 5 quema (DEL+denylist). Retorna burned.
	RecordFail(ctx context.Context, challengeID string) (burned bool, err error)
	// MarkReplay SET NX EX 90; fresh=false → replay (401 aunque cripto OK).
	MarkReplay(ctx context.Context, userID string, counter int64) (fresh bool, err error)
	// Uncheckable indica si el reuso NO pudo verificarse (Redis+DB caídos).
	// Con true el servicio responde 500 REPLAY_UNCHECKABLE, no 401.
	Uncheckable(ctx context.Context) bool
}

