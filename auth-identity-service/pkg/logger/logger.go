package logger

import (
	"log/slog"
	"os"
)

// New logger JSON estructurado (slog) sin PII.
func New(service string) *slog.Logger {
	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	return slog.New(h).With("service", service)
}
