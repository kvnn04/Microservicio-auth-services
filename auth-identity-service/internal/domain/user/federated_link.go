package user

import "context"

// LinkedIdentity resume un vínculo para listado (PII minimizada, SEC-03).
type LinkedIdentity struct {
	Provider    Provider
	EmailMasked string
	SubHash8    string
	EmailAtLink string
	LinkedAt    string
}

// FederatedLinkStore extiende FederatedRepository (CU-REG-04) con link/unlink.
type FederatedLinkStore interface {
	FederatedRepository
	// LinkTx vincula (provider,sub)→userID en Tx + outbox + mails.
	// Mapea: self→ErrAlreadyLinkedSelf, otro→ErrCollisionForeign,
	// provider tomado→ErrProviderTaken. Nunca mueve subs entre cuentas.
	LinkTx(ctx context.Context, f *FederatedIdentity, outbox []OutboxPayload, mails []MailPayload) error
	// UnlinkTx desvincula provider de userID + outbox + mail aviso.
	// Retorna linked=false si no existía (→404 FEDERATED_NOT_LINKED).
	UnlinkTx(ctx context.Context, userID string, p Provider, outbox []OutboxPayload, mail MailPayload) (linked bool, err error)
	// ListByUser retorna vínculos + si tiene password local.
	ListByUser(ctx context.Context, userID string) (links []FederatedIdentity, hasPassword bool, err error)
}

// LinkState representa fed:link:<state> (ligado a user_id, RN-02).
type LinkState struct {
	UserID    string
	Nonce     string
	Verifier  string
	IPHash    string
	CreatedAt int64
}

// LinkStateStore puerto de estado link (fail-closed si cae, §4.3).
type LinkStateStore interface {
	SaveLinkState(ctx context.Context, state string, st LinkState) error
	// ConsumeLinkState GET+DEL atómico; miss → ErrNotFound (→400).
	ConsumeLinkState(ctx context.Context, state string) (LinkState, error)
}
