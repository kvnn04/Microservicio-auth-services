package http

import (
	"auth-identity-service/internal/service"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	plessTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "passwordless_total", Help: "Passwordless por operación y resultado.",
	}, []string{"op", "result"})
	plessDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "passwordless_duration_seconds", Help: "Duración passwordless.",
		Buckets: []float64{0.05, 0.1, 0.2, 0.5, 1, 2},
	}, []string{"op"})
	plessMismatch = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pless_context_mismatch_total", Help: "Consumos high-risk.",
	}, []string{"risk"})
	plessFallback = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pless_redis_fallback_total", Help: "Fallbacks Redis→Postgres.",
	}, []string{"reason"})
)

// PrometheusPlessMetrics implementa service.PlessMetricsPort (CU-AUTH-05 T-05).
type PrometheusPlessMetrics struct{}

func NewPrometheusPlessMetrics() *PrometheusPlessMetrics { return &PrometheusPlessMetrics{} }

func (PrometheusPlessMetrics) IncPless(op, r string) { plessTotal.WithLabelValues(op, r).Inc() }
func (PrometheusPlessMetrics) ObservePlessDuration(op string, v float64) {
	plessDuration.WithLabelValues(op).Observe(v)
}
func (PrometheusPlessMetrics) IncMismatch(risk string) { plessMismatch.WithLabelValues(risk).Inc() }
func (PrometheusPlessMetrics) IncPlessFallback(reason string) {
	plessFallback.WithLabelValues(reason).Inc()
}

var _ service.PlessMetricsPort = PrometheusPlessMetrics{}
