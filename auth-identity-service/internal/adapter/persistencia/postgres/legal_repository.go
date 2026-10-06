package postgres

import (
	"context"
	"errors"
	"fmt"

	redisadapter "auth-identity-service/internal/adapter/persistencia/redis"
	"auth-identity-service/internal/domain/shared"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// LegalRepository implementa shared.LegalVersionProvider + shared.ConsentLedger.
type LegalRepository struct {
	pool *pgxpool.Pool
}

func NewLegalRepository(pool *pgxpool.Pool) *LegalRepository {
	return &LegalRepository{pool: pool}
}

// GetActive retorna las 2 vigentes desde DB (revalida aunque haya cache).
// Falla fail-closed (ErrLegalInfra) si DB cae — register nunca usa fallback.
func (r *LegalRepository) GetActive(ctx context.Context) (shared.LegalDocument, shared.LegalDocument, error) {
	if r == nil || r.pool == nil {
		return shared.LegalDocument{}, shared.LegalDocument{}, fmt.Errorf("no pool: %w", shared.ErrLegalInfra)
	}
	const q = `SELECT doc_type, version, content_hash, url, effective_from, is_active
		FROM legal_versions WHERE is_active = TRUE`
	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return shared.LegalDocument{}, shared.LegalDocument{}, fmt.Errorf("select legal: %w", shared.ErrLegalInfra)
	}
	defer rows.Close()
	docs := map[shared.DocType]shared.LegalDocument{}
	for rows.Next() {
		var d shared.LegalDocument
		var dt string
		if err := rows.Scan(&dt, &d.Version, &d.ContentHash, &d.URL, &d.EffectiveFrom, &d.IsActive); err != nil {
			return shared.LegalDocument{}, shared.LegalDocument{}, fmt.Errorf("scan legal: %w", shared.ErrLegalInfra)
		}
		d.DocType = shared.DocType(dt)
		docs[d.DocType] = d
	}
	t, okT := docs[shared.DocTerms]
	p, okP := docs[shared.DocPrivacy]
	if !okT || !okP {
		return shared.LegalDocument{}, shared.LegalDocument{}, fmt.Errorf("missing active: %w", shared.ErrLegalInfra)
	}
	return t, p, nil
}

// RecordTx inserta en la Tx de negocio (tx opaca any → cast pgx.Tx).
// ON CONFLICT DO NOTHING: replay mismo RequestID no duplica.
func (r *LegalRepository) RecordTx(ctx context.Context, tx any, recs []shared.ConsentRecord) error {
	ptx, ok := tx.(pgx.Tx)
	if !ok {
		return fmt.Errorf("tx type: %w", shared.ErrLegalInfra)
	}
	for _, rec := range recs {
		uid, err := uuid.Parse(rec.UserID)
		if err != nil {
			return err
		}
		rid, err := uuid.Parse(rec.RequestID)
		if err != nil {
			return err
		}
		if _, err := ptx.Exec(ctx, `INSERT INTO consent_records
			(id, user_id, doc_type, version, accepted_at, ip_hash, ua_hash, source, request_id)
			VALUES (gen_random_uuid(),$1,$2,$3,$4,$5,$6,$7,$8)
			ON CONFLICT (user_id, doc_type, version) DO NOTHING`,
			uid, string(rec.DocType), rec.Version, rec.AcceptedAt,
			rec.IPHash, rec.UAHash, rec.Source, rid,
		); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			return fmt.Errorf("insert consent: %w", err)
		}
	}
	return nil
}

// CombinedLegalProvider combina DB (verdad) + Redis (lectura) + fallback env.
// GetActive (register): DB directo SIEMPRE, fail-closed sin fallback.
// GetActivePublic (GET /legal/active): cache → DB → fallback env (stale).
type CombinedLegalProvider struct {
	db              *LegalRepository
	cache           *redisadapter.LegalCache
	fallbackTerms   shared.LegalDocument
	fallbackPrivacy shared.LegalDocument
	hasFallback     bool
	onStale         func()
}

func NewCombinedLegalProvider(pool *pgxpool.Pool, cache *redisadapter.LegalCache, fallbackTerms, fallbackPrivacy string, onStale func()) *CombinedLegalProvider {
	c := &CombinedLegalProvider{db: NewLegalRepository(pool), cache: cache, onStale: onStale}
	if fallbackTerms != "" && fallbackPrivacy != "" {
		c.hasFallback = true
		c.fallbackTerms = shared.LegalDocument{DocType: shared.DocTerms, Version: fallbackTerms}
		c.fallbackPrivacy = shared.LegalDocument{DocType: shared.DocPrivacy, Version: fallbackPrivacy}
	}
	return c
}

func (c *CombinedLegalProvider) GetActive(ctx context.Context) (shared.LegalDocument, shared.LegalDocument, error) {
	return c.db.GetActive(ctx)
}

func (c *CombinedLegalProvider) GetActivePublic(ctx context.Context) (terms, privacy shared.LegalDocument, stale bool, err error) {
	// Fast-path: cache-hit directo (rotación <1h vía TTL, spec §4.5).
	if c.cache != nil {
		if t, p, ok := c.cache.Get(ctx); ok {
			return t, p, false, nil
		}
	}
	if t, p, derr := c.db.GetActive(ctx); derr == nil {
		if c.cache != nil {
			c.cache.Set(ctx, t, p)
		}
		return t, p, false, nil
	} else {
		err = derr
	}
	// Degradado: si la DB falló pero había cache... ya se intentó arriba.
	// Reintenta cache por si la pobló otro request concurrente.
	if c.cache != nil {
		if t, p, ok := c.cache.Get(ctx); ok {
			if c.onStale != nil {
				c.onStale()
			}
			return t, p, true, nil
		}
	}
	if c.hasFallback {
		if c.onStale != nil {
			c.onStale()
		}
		return c.fallbackTerms, c.fallbackPrivacy, true, nil
	}
	return shared.LegalDocument{}, shared.LegalDocument{}, false, err
}
