package redis

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// IdempotencyStore implementa shared.IdempotencyStore en Redis (TTL 24h).
type IdempotencyStore struct {
	client *redis.Client
}

func NewIdempotencyStore(client *redis.Client) *IdempotencyStore {
	return &IdempotencyStore{client: client}
}

func (s *IdempotencyStore) Get(ctx context.Context, requestID string) (string, bool, error) {
	v, err := s.client.Get(ctx, "idem:"+requestID).Result()
	if err == redis.Nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

func (s *IdempotencyStore) Put(ctx context.Context, requestID, responseHash string, ttl time.Duration) error {
	return s.client.Set(ctx, "idem:"+requestID, responseHash, ttl).Err()
}
