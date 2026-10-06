package redis

import (
	"context"
	"encoding/json"
	"errors"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/user"

	"github.com/redis/go-redis/v9"
)

// Clave de estado federado: fed:state:<statehex> EX 600 NX.
// Valor JSON {nonce, verifier, ip_hash, return_to, created_at}.
// Fail-closed: si Redis cae, callback → 500 (sin estado no hay seguridad).
func fedStateKey(state string) string { return "fed:state:" + state }

// RedisFederatedStateStore implementa auth.FederatedStateStore.
type RedisFederatedStateStore struct {
	client *redis.Client
}

func NewRedisFederatedStateStore(client *redis.Client) *RedisFederatedStateStore {
	return &RedisFederatedStateStore{client: client}
}

func (s *RedisFederatedStateStore) SaveState(ctx context.Context, state string, st auth.FederatedState) error {
	if s.client == nil {
		return errors.New("redis unavailable")
	}
	body, _ := json.Marshal(map[string]any{
		"nonce": st.Nonce, "verifier": st.Verifier, "ip_hash": st.IPHash,
		"return_to": st.ReturnTo, "created_at": st.CreatedAt,
		"terms_version": st.TermsVersion, "privacy_version": st.PrivacyVersion,
	})
	ok, err := s.client.SetNX(ctx, fedStateKey(state), string(body), auth.FederatedStateTTL).Result()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("state already exists")
	}
	return nil
}

var luaConsumeState = redis.NewScript(`
	local v = redis.call('GET', KEYS[1])
	if not v then return nil end
	redis.call('DEL', KEYS[1])
	return v`)

// ConsumeState GET+DEL atómico. Miss → user.ErrNotFound (→400); down → error (→500).
func (s *RedisFederatedStateStore) ConsumeState(ctx context.Context, state string) (auth.FederatedState, error) {
	if s.client == nil {
		return auth.FederatedState{}, errors.New("redis unavailable")
	}
	raw, err := luaConsumeState.Run(ctx, s.client, []string{fedStateKey(state)}).Text()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return auth.FederatedState{}, user.ErrNotFound
		}
		return auth.FederatedState{}, err
	}
	var m map[string]any
	if jerr := json.Unmarshal([]byte(raw), &m); jerr != nil {
		return auth.FederatedState{}, user.ErrNotFound
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
	return auth.FederatedState{
		Nonce: str("nonce"), Verifier: str("verifier"),
		IPHash: str("ip_hash"), ReturnTo: str("return_to"), CreatedAt: created,
		TermsVersion: str("terms_version"), PrivacyVersion: str("privacy_version"),
	}, nil
}
