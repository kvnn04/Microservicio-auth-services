package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"auth-identity-service/internal/adapter/colas/kafka"
	"auth-identity-service/internal/adapter/persistencia/postgres"
	redisadapter "auth-identity-service/internal/adapter/persistencia/redis"
	"auth-identity-service/pkg/logger"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

func mustEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	log := logger.New("worker")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	dbURL := mustEnv("DATABASE_URL", "postgres://auth:auth@localhost:5432/auth_db?sslmode=disable")
	brokers := strings.Split(mustEnv("KAFKA_BROKERS", "localhost:9092"), ",")

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Error("postgres connect failed", slog.String("error_code", "DB_UNAVAILABLE"))
		os.Exit(1)
	}
	defer pool.Close()

	relay := kafka.NewOutboxRelay(pool, brokers)
	mailer := kafka.NewEmailMailer(pool,
		mustEnv("MAIL_SMTP_ADDR", "localhost:1025"),
		mustEnv("MAIL_FROM", "no-reply@example.com"))
	mailer.SetFrontURL(mustEnv("FRONT_BASE_URL", "http://localhost:3000"))
	// Reconciliador CU-REG-02: limpia claves Redis huérfanas cada 10s.
	var vstore *postgres.CombinedVerificationStore
	if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
		rdb := redis.NewClient(&redis.Options{Addr: redisAddr(redisURL)})
		vstore = postgres.NewCombinedVerificationStore(pool,
			redisadapter.NewVerificationCache(rdb),
			mustEnv("FRONT_BASE_URL", "http://localhost:3000"), nil)
	}
	log.Info("worker started", slog.String("brokers", strings.Join(brokers, ",")))
	go func() {
		if err := relay.Run(ctx); err != nil && context.Cause(ctx) == nil {
			log.Error("relay failed", slog.String("error", err.Error()))
		}
	}()
	go func() {
		if err := mailer.Run(ctx); err != nil && context.Cause(ctx) == nil {
			log.Error("mailer failed", slog.String("error", err.Error()))
		}
	}()
	if vstore != nil {
		go func() {
			t := time.NewTicker(10 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					vstore.Reconcile(ctx)
				}
			}
		}()
	}
	<-ctx.Done()
	log.Info("worker stopped")
}

func redisAddr(url string) string {
	s := strings.TrimPrefix(url, "redis://")
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return "localhost:6379"
	}
	return s
}
