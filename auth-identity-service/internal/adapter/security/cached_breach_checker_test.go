package security

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// fakeInner implementa auth.BreachChecker + rangeFetcher con respuestas
// programadas y contador de llamadas.
type fakeInner struct {
	calls int64
	raw   string
	err   error
}

func (f *fakeInner) IsCompromised(_ context.Context, password string) (bool, error) {
	atomic.AddInt64(&f.calls, 1)
	if f.err != nil {
		return false, f.err
	}
	sum := sha1.Sum([]byte(password))
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	return strings.Contains(f.raw, full[5:]), nil
}

func (f *fakeInner) FetchRange(_ context.Context, _ string) (string, error) {
	atomic.AddInt64(&f.calls, 1)
	if f.err != nil {
		return "", f.err
	}
	return f.raw, nil
}

type fakeCacheMetrics struct {
	mu sync.Mutex
	n  map[string]int
}

func (f *fakeCacheMetrics) IncHibpCache(r string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.n == nil {
		f.n = map[string]int{}
	}
	f.n[r]++
}

func newTestRedis(t *testing.T) (*redis.Client, func()) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Skipf("sin miniredis: %v", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return rdb, func() { _ = rdb.Close(); mr.Close() }
}

func prefixOf(password string) string {
	sum := sha1.Sum([]byte(password))
	return strings.ToUpper(hex.EncodeToString(sum[:]))[:5]
}

func TestCachedHit(t *testing.T) {
	rdb, done := newTestRedis(t)
	defer done()
	ctx := context.Background()
	inner := &fakeInner{raw: "003D68BAA6D9A6A5477F2EB2F736A56E7B8:3\n"}
	pw := "Str0ng!Passw0rd-2026"
	// La respuesta contiene el sufijo de este password o no; lo que importa:
	// con el bucket pre-sembrado el inner NO debe llamarse.
	m := &fakeCacheMetrics{}
	c := NewCachedBreachChecker(inner, rdb, m)
	if err := rdb.Set(ctx, hibpCacheKey(prefixOf(pw)), inner.raw, HIBPCacheTTL).Err(); err != nil {
		t.Fatal(err)
	}
	got, err := c.IsCompromised(ctx, pw)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha1.Sum([]byte(pw))
	want := strings.Contains(inner.raw, strings.ToUpper(hex.EncodeToString(sum[:]))[5:])
	if got != want {
		t.Fatalf("hit: got %v want %v", got, want)
	}
	if atomic.LoadInt64(&inner.calls) != 0 {
		t.Fatalf("hit llamó al inner %d veces", inner.calls)
	}
	if m.n["hit"] != 1 {
		t.Fatalf("métrica hit: %v", m.n)
	}
}

func TestCachedMissStores(t *testing.T) {
	rdb, done := newTestRedis(t)
	defer done()
	ctx := context.Background()
	inner := &fakeInner{raw: "AAAAA00000000000000000000000000000:2\n"}
	m := &fakeCacheMetrics{}
	c := NewCachedBreachChecker(inner, rdb, m)
	if _, err := c.IsCompromised(ctx, "Otro!Passw0rd-2026"); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt64(&inner.calls) != 1 {
		t.Fatalf("miss debió llamar 1 vez, fueron %d", inner.calls)
	}
	ttl, err := rdb.TTL(ctx, hibpCacheKey(prefixOf("Otro!Passw0rd-2026"))).Result()
	if err != nil || ttl <= 55*time.Minute || ttl > HIBPCacheTTL {
		t.Fatalf("TTL: %v %v", ttl, err)
	}
	if m.n["miss"] != 1 {
		t.Fatalf("métrica miss: %v", m.n)
	}
	// Segunda vez: hit, sin nueva llamada.
	if _, err := c.IsCompromised(ctx, "Otro!Passw0rd-2026"); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt64(&inner.calls) != 1 {
		t.Fatalf("segunda debió ser hit, calls=%d", inner.calls)
	}
}

func TestCachedInnerError(t *testing.T) {
	rdb, done := newTestRedis(t)
	defer done()
	inner := &fakeInner{err: errors.New("hibp caído")}
	c := NewCachedBreachChecker(inner, rdb, &fakeCacheMetrics{})
	if _, err := c.IsCompromised(context.Background(), "Xx!Passw0rd-2026"); err == nil {
		t.Fatal("debió propagar el error (el servicio aplica local-deny)")
	}
	if n, _ := rdb.Exists(context.Background(), hibpCacheKey(prefixOf("Xx!Passw0rd-2026"))).Result(); n != 0 {
		t.Fatal("error no debe cachearse")
	}
}

func TestCachedRedisDown(t *testing.T) {
	mr, _ := miniredis.Run()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	mr.Close() // Redis "caído" de acá en más.
	inner := &fakeInner{raw: ""}
	c := NewCachedBreachChecker(inner, rdb, &fakeCacheMetrics{})
	if _, err := c.IsCompromised(context.Background(), "Yy!Passw0rd-2026"); err != nil {
		t.Fatalf("Redis caído debe degradar a llamada directa: %v", err)
	}
	_ = rdb.Close()
}

func TestCachedHerd(t *testing.T) {
	rdb, done := newTestRedis(t)
	defer done()
	inner := &fakeInner{raw: ""}
	c := NewCachedBreachChecker(inner, rdb, &fakeCacheMetrics{})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.IsCompromised(context.Background(), "Herd!Pass-0000-2026")
		}()
	}
	wg.Wait()
	// Mismo prefijo ×20 concurrentes → exactamente 1 llamada HIBP.
	if atomic.LoadInt64(&inner.calls) != 1 {
		t.Fatalf("herd no colapsado: %d llamadas", inner.calls)
	}
}
