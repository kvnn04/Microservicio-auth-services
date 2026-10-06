package redis

import (
	"context"
	"encoding/json"
	"errors"

	"auth-identity-service/internal/domain/auth"

	"github.com/redis/go-redis/v9"
)

// Clave CU-AUTH-06 (sin PII: solo UUIDs + scope enum):
//
//	stepup:jti:<jti>  JSON {sub, scope} NX EX 300 (single-use)
func stepUpJTIKey(jti string) string { return "stepup:jti:" + jti }

type stepUpJTIValue struct {
	Sub   string `json:"sub"`
	Scope string `json:"scope"`
}

// StepUpJTIStore implementa auth.StepUpJTIStore (single-use de jti).
// Fail-closed: client nil o error → el servicio responde 500
// STEP_UP_UNAVAILABLE (el fast-pass offline con JWT no usa Redis).
type StepUpJTIStore struct {
	client *redis.Client
}

func NewStepUpJTIStore(client *redis.Client) *StepUpJTIStore {
	return &StepUpJTIStore{client: client}
}

var errStepUpNoRedis = errors.New("step-up store unavailable")

// Save registra jti virgen (NX EX 300). Colisión UUIDv7 ~imposible;
// si existiera, el servicio reintenta con nuevo jti (no implementado:
// retorna error → Unavailable, fail-closed).
func (s *StepUpJTIStore) Save(ctx context.Context, jti, sub, scope string) error {
	if s.client == nil {
		return errStepUpNoRedis
	}
	body, _ := json.Marshal(stepUpJTIValue{Sub: sub, Scope: scope})
	ok, err := s.client.SetNX(ctx, stepUpJTIKey(jti), string(body), auth.StepUpTokenTTL).Result()
	if err != nil {
		return err
	}
	if !ok {
		return errStepUpNoRedis
	}
	return nil
}

// Consume quema atómicamente (Lua GET+DEL). found=false → ya usado.
func (s *StepUpJTIStore) Consume(ctx context.Context, jti string) (string, string, bool, error) {
	if s.client == nil {
		return "", "", false, errStepUpNoRedis
	}
	script := redis.NewScript(`
		local v = redis.call('GET', KEYS[1])
		if not v then return nil end
		redis.call('DEL', KEYS[1])
		return v`)
	raw, err := script.Run(ctx, s.client, []string{stepUpJTIKey(jti)}).Text()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", "", false, nil
		}
		return "", "", false, err
	}
	var v stepUpJTIValue
	if jerr := json.Unmarshal([]byte(raw), &v); jerr != nil || v.Sub == "" {
		return "", "", false, nil
	}
	return v.Sub, v.Scope, true, nil
}

var _ auth.StepUpJTIStore = (*StepUpJTIStore)(nil)
