package user

import "context"

// FederatedRepository puerto de persistencia federada (CU-REG-04).
type FederatedRepository interface {
	// FindByProviderSub retorna identidad + usuario (JOIN). ErrNotFound si miss.
	FindByProviderSub(ctx context.Context, p Provider, sub string) (*FederatedIdentity, *User, error)
	// FindUserByEmailNormalized lookup canónico (anti-takeover).
	FindUserByEmailNormalized(ctx context.Context, email string) (*User, error)
	// CreateUserWithFederation Tx atómica: users + link + outbox (+email_queue).
	// Carrera UNIQUE(provider,sub)→ErrAlreadyLinked; UNIQUE(email)→ErrEmailCollision.
	// CU-REG-05: reg porta atribución legal (ledger + evento en la misma Tx).
	CreateUserWithFederation(ctx context.Context, u *User, f *FederatedIdentity, outbox []OutboxPayload, mail MailPayload, reg RegistrationContext) error
}

// MailPayload email transaccional con secreto (solo worker SMTP, nunca Kafka).
type MailPayload struct {
	To      string
	Subject string
	Body    string
}
