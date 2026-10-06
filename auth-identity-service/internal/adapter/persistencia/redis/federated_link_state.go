package redis

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"auth-identity-service/internal/domain/user"

	"github.com/redis/go-redis/v9"
)

// Clave link: fed:link:<statehex> EX 600 NX.
// Valor JSON {user_id, nonce, verifier, ip_hash, created_at}.
// Fail-closed: caído → 500 LINK_STATE_UNAVAILABLE (sin estado no hay anti-fijación).
func fedLinkKey(state string) string { return "fed:link:" + state }

// RedisLinkStateStore implementa user.LinkStateStore.
type RedisLinkStateStore struct {
	client *redis.Client
}

func NewRedisLinkStateStore(client *redis.Client) *RedisLinkStateStore {
	return &RedisLinkStateStore{client: client}
}

func (s *RedisLinkStateStore) SaveLinkState(ctx context.Context, state string, st user.LinkState) error {
	if s.client == nil {
		return errors.New("redis unavailable")
	}
	body, _ := json.Marshal(map[string]any{
		"user_id": st.UserID, "nonce": st.Nonce, "verifier": st.Verifier,
		"ip_hash": st.IPHash, "created_at": st.CreatedAt,
	})
	ok, err := s.client.SetNX(ctx, fedLinkKey(state), string(body), 10*time.Minute).Result()
	_ = ok
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("link state already exists")
	}
	return nil
}

var luaConsumeLinkState = redis.NewScript(`
	local v = redis.call('GET', KEYS[1])
	if not v then return nil end
	redis.call('DEL', KEYS[1])
	return v`)

// ConsumeLinkState GET+DEL atómico; miss → user.ErrNotFound (→400).
func (s *RedisLinkStateStore) ConsumeLinkState(ctx context.Context, state string) (user.LinkState, error) {
	if s.client == nil {
		return user.LinkState{}, errors.New("redis unavailable")
	}
	raw, err := luaConsumeLinkState.Run(ctx, s.client, []string{fedLinkKey(state)}).Text()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return user.LinkState{}, user.ErrNotFound
		}
		return user.LinkState{}, err
	}
	var m map[string]any
	if jerr := json.Unmarshal([]byte(raw), &m); jerr != nil {
		return user.LinkState{}, user.ErrNotFound
	}
	str := func(k string) string {
		if v, ok := m[k].(string); ok {
			return v
		}
		return ""
	}
	var created int64
	if v, ok := m["created_at"].(float64); ok {
		created = int64(v)
	}
	return user.LinkState{
		UserID: str("user_id"), Nonce: str("nonce"), Verifier: str("verifier"),
		IPHash: str("ip_hash"), CreatedAt: created,
	}, nil
}
