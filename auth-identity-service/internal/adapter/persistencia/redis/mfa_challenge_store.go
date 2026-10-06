package redis

import (
	"github.com/redis/go-redis/v9"
)

// Claves MFA CU-AUTH-02 (secretos/códigos jamás en Redis, solo IDs/contadores):
//   mfa:challenge:<id>  user_id EX 300 (single-use)
//   mfa:deny:<id>        "1" EX 300 (quemados)
//   mfa:fails:<id>       contador EX 300 (a 5 quema)
//   mfa:used:<u>:<c>     "1" NX EX 90 (anti-replay)
// La lógica vive en postgres.MFAStores (Redis-primario + DB-fallback);
// este tipo conserva el cliente para futuros espejos (staged).
type MFAChallengeCache struct {
	client *redis.Client
}

func NewMFAChallengeCache(client *redis.Client) *MFAChallengeCache {
	return &MFAChallengeCache{client: client}
}

// Client expone el cliente subyacente.
func (c *MFAChallengeCache) Client() *redis.Client { return c.client }
