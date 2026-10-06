package redis

import (
	"context"
	"testing"

	"github.com/redis/go-redis/v9"
)

func testRedisClient(t *testing.T) *redis.Client {
	t.Helper()
	c := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	if err := c.Ping(context.Background()).Err(); err != nil {
		t.Skipf("sin redis: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestStepUpJTI_SaveConsumeUnUso(t *testing.T) {
	s := NewStepUpJTIStore(testRedisClient(t))
	ctx := context.Background()
	jti := "test-jti-un-uso"
	_ = s.client.Del(ctx, stepUpJTIKey(jti)).Err()
	if err := s.Save(ctx, jti, "user-1", "cred:change-password"); err != nil {
		t.Fatalf("save: %v", err)
	}
	sub, scope, found, err := s.Consume(ctx, jti)
	if err != nil || !found || sub != "user-1" || scope != "cred:change-password" {
		t.Fatalf("consume: %v %v %q %q", err, found, sub, scope)
	}
	// Replay → miss (quemado).
	_, _, found, err = s.Consume(ctx, jti)
	if err != nil || found {
		t.Fatalf("replay debe ser miss: %v %v", err, found)
	}
}

func TestStepUpJTI_FailClosed(t *testing.T) {
	s := NewStepUpJTIStore(nil)
	ctx := context.Background()
	if err := s.Save(ctx, "j", "u", "s"); err == nil {
		t.Fatal("sin Redis Save debe fallar (fail-closed)")
	}
	if _, _, _, err := s.Consume(ctx, "j"); err == nil {
		t.Fatal("sin Redis Consume debe fallar (fail-closed)")
	}
}
