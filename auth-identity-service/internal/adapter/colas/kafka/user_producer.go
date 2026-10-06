package kafka

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/kafka-go"
)

// OutboxRelay lee outbox pendiente y publica a Kafka. Backoff + DLQ.
type OutboxRelay struct {
	pool     *pgxpool.Pool
	writer   *kafka.Writer
	dlqTopic string
}

func NewOutboxRelay(pool *pgxpool.Pool, brokers []string) *OutboxRelay {
	w := &kafka.Writer{
		Addr: kafka.TCP(brokers...), Balancer: &kafka.Hash{},
		RequiredAcks: kafka.RequireAll,
	}
	return &OutboxRelay{pool: pool, writer: w, dlqTopic: "auth.dlq.v1"}
}

func (r *OutboxRelay) Run(ctx context.Context) error {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	defer r.writer.Close()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			_ = r.DrainOnce(ctx, 100)
		}
	}
}

func (r *OutboxRelay) DrainOnce(ctx context.Context, limit int) error {
	const q = `SELECT event_id::text, event_type, aggregate_id::text, topic, payload, attempts
		FROM outbox WHERE status='pending' ORDER BY created_at ASC LIMIT $1`
	rows, err := r.pool.Query(ctx, q, limit)
	if err != nil {
		return fmt.Errorf("select outbox: %w", err)
	}
	type item struct {
		eventID, eventType, agg, topic, payload string
		attempts                               int
	}
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.eventID, &it.eventType, &it.agg, &it.topic, &it.payload, &it.attempts); err != nil {
			rows.Close()
			return err
		}
		items = append(items, it)
	}
	rows.Close()
	for _, it := range items {
		msg := kafka.Message{
			Topic: it.topic, Key: []byte(it.agg), Value: []byte(it.payload),
			Headers: []kafka.Header{
				{Key: "event_id", Value: []byte(it.eventID)},
				{Key: "event_type", Value: []byte(it.eventType)},
			},
		}
		if err := r.writer.WriteMessages(ctx, msg); err != nil {
			_, _ = r.pool.Exec(ctx, `UPDATE outbox SET attempts = attempts + 1 WHERE event_id = $1::uuid`, it.eventID)
			if it.attempts > 50 {
				_, _ = r.pool.Exec(ctx, `UPDATE outbox SET status='failed' WHERE event_id=$1::uuid`, it.eventID)
				_ = r.writer.WriteMessages(ctx, kafka.Message{
					Topic: r.dlqTopic, Key: []byte(it.agg), Value: []byte(it.payload),
					Headers: []kafka.Header{{Key: "original-topic", Value: []byte(it.topic)}},
				})
			}
			continue
		}
		_, _ = r.pool.Exec(ctx, `UPDATE outbox SET status='sent', sent_at=now() WHERE event_id=$1::uuid`, it.eventID)
	}
	return nil
}
