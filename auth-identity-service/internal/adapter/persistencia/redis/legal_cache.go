package redis

import (
	"context"
	"encoding/json"
	"time"

	"auth-identity-service/internal/domain/shared"

	"github.com/redis/go-redis/v9"
)

// Clave de lectura legal: legal:active EX 3600 (JSON activas + fetched_at).
// Solo fast-path de lectura; register revalida DB directo (fail-closed).
func legalActiveKey() string { return "legal:active" }

type cachedLegal struct {
	Terms     shared.LegalDocument `json:"terms"`
	Privacy   shared.LegalDocument `json:"privacy"`
	FetchedAt int64                `json:"fetched_at"`
}

// LegalCache fast-path de lectura para GET /legal/active.
type LegalCache struct {
	client *redis.Client
	ttl    time.Duration
}

func NewLegalCache(client *redis.Client) *LegalCache {
	return &LegalCache{client: client, ttl: time.Hour}
}

func (c *LegalCache) Get(ctx context.Context) (terms, privacy shared.LegalDocument, ok bool) {
	if c.client == nil {
		return shared.LegalDocument{}, shared.LegalDocument{}, false
	}
	raw, err := c.client.Get(ctx, legalActiveKey()).Result()
	if err != nil {
		return shared.LegalDocument{}, shared.LegalDocument{}, false
	}
	var cl cachedLegal
	if err := json.Unmarshal([]byte(raw), &cl); err != nil {
		return shared.LegalDocument{}, shared.LegalDocument{}, false
	}
	return cl.Terms, cl.Privacy, true
}

func (c *LegalCache) Set(ctx context.Context, terms, privacy shared.LegalDocument) {
	if c.client == nil {
		return
	}
	raw, _ := json.Marshal(cachedLegal{Terms: terms, Privacy: privacy, FetchedAt: time.Now().Unix()})
	_ = c.client.Set(ctx, legalActiveKey(), string(raw), c.ttl).Err()
}

// Purge invalida tras publicación de versión (Tx admin la llama).
func (c *LegalCache) Purge(ctx context.Context) {
	if c.client == nil {
		return
	}
	_ = c.client.Del(ctx, legalActiveKey()).Err()
}
