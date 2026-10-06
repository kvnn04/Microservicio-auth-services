package http

import (
	"context"

	"auth-identity-service/internal/service"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

// OtelTracer implementa service.TracerPort.
type OtelTracer struct {
	tracer trace.Tracer
}

func NewOtelTracer() *OtelTracer {
	return &OtelTracer{tracer: otel.Tracer("auth-identity-service")}
}

type otelSpan struct{ s trace.Span }

func (o otelSpan) End() { o.s.End() }

func (t *OtelTracer) Start(ctx context.Context, name string) (context.Context, service.Span) {
	ctx, s := t.tracer.Start(ctx, name)
	return ctx, otelSpan{s: s}
}

var _ service.TracerPort = (*OtelTracer)(nil)
