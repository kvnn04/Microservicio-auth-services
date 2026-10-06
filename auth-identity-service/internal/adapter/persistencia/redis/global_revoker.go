package redis

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// Claves CU-SES-02 (sin PII: solo UUIDs):
//
//	sess:by_user:<sub>  SET de sids EX 90d (índice mantenido desde Issue;
//	                    el corte lo barre y lo borra; si falta —sesiones
//	                    pre-017— el worker lo repara con SCAN acotado)
//	mfa:challenge:by_user:<sub>  (si algún flujo lo indexa; si no existe,
//	                    el DEL es no-op y el TTL residual se documenta)
const (
	revokedAllChannel = "auth.session.revoked_all"
	byUserTTL         = 90 * 24 * time.Hour
)

// SessByUserKey índice sids-por-usuario para el barrido global.
func SessByUserKey(userID string) string { return "sess:by_user:" + userID }

// MFAChallengeByUserKey índice best-effort de challenges por usuario.
func MFAChallengeByUserKey(userID string) string { return "mfa:challenge:by_user:" + userID }

// GlobalSweep barrido Redis post-commit del corte global (CU-SES-02 T-08).
// Best-effort: cualquier error se reporta al llamador (que lo cuenta como
// fallback WARN) sin revertir la Tx PG, que es la verdad.
type GlobalSweep struct {
	client *redis.Client
}

func NewGlobalSweep(client *redis.Client) *GlobalSweep {
	return &GlobalSweep{client: client}
}

// Sweep borra huellas de caché del usuario: sess:<sid> (miembros del índice
// + sids PG por tolerancia a miembros muertos), fam:<family>, jti:<jti>,
// el propio índice by_user y challenges indexados. sids/families/jtis
// vienen de la Tx PG (verdad); el índice aporta cobertura Redis-only.
func (s *GlobalSweep) Sweep(ctx context.Context, userID string, sids, families, jtis []string) error {
	if s.client == nil {
		return redis.ErrClosed
	}
	members, _ := s.client.SMembers(ctx, SessByUserKey(userID)).Result()
	seen := map[string]bool{}
	var sessKeys []string
	for _, sid := range append(append([]string{}, sids...), members...) {
		if sid == "" || seen[sid] {
			continue
		}
		seen[sid] = true
		sessKeys = append(sessKeys, sessKey(sid))
	}
	pipe := s.client.Pipeline()
	for _, k := range sessKeys {
		pipe.Del(ctx, k)
	}
	seenFam := map[string]bool{}
	for _, f := range families {
		if f == "" || seenFam[f] {
			continue
		}
		seenFam[f] = true
		pipe.Del(ctx, famKey(f))
	}
	for _, j := range jtis {
		if j != "" {
			pipe.Del(ctx, jtiKey(j))
		}
	}
	pipe.Del(ctx, SessByUserKey(userID))
	// Best-effort challenges indexados (si no existen → no-op; el resto
	// expira por TTL — ventana residual documentada en §4.5).
	pipe.Del(ctx, MFAChallengeByUserKey(userID))
	_, err := pipe.Exec(ctx)
	return err
}

// PublishRevoked avisa a gateways suscritos para invalidar su cache de
// valid_after en ~1s (además de Kafka durable). Sin suscriptores el mensaje
// se pierde sin error — el outbox sigue siendo la verdad.
func (s *GlobalSweep) PublishRevoked(ctx context.Context, payload string) error {
	if s.client == nil {
		return redis.ErrClosed
	}
	return s.client.Publish(ctx, revokedAllChannel, payload).Err()
}

// RevokedAllChannel canal pub/sub del corte global (gateways).
func RevokedAllChannel() string { return revokedAllChannel }
