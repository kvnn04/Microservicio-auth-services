package http

import (
	"auth-identity-service/internal/service"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	emailChangeTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "email_change_total", Help: "Cambios de correo por operación y resultado.",
	}, []string{"op", "result"})
	emailChangeDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "email_change_duration_seconds", Help: "Duración cambio de correo.",
		Buckets: []float64{0.05, 0.1, 0.2, 0.5, 1, 2},
	}, []string{"op"})
	emailChangeFallback = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "emailchange_redis_fallback_total", Help: "Fallbacks Redis→Postgres.",
	}, []string{"reason"})
)

// PrometheusEmailChangeMetrics implementa service.EmailChangeMetricsPort (CU-CRED-03 T-05).
type PrometheusEmailChangeMetrics struct{}

func NewPrometheusEmailChangeMetrics() *PrometheusEmailChangeMetrics {
	return &PrometheusEmailChangeMetrics{}
}

func (PrometheusEmailChangeMetrics) IncEmailChange(op, r string) { emailChangeTotal.WithLabelValues(op, r).Inc() }
func (PrometheusEmailChangeMetrics) ObserveEmailChangeDuration(op string, v float64) {
	emailChangeDuration.WithLabelValues(op).Observe(v)
}
func (PrometheusEmailChangeMetrics) IncEmailChangeFallback(reason string) {
	emailChangeFallback.WithLabelValues(reason).Inc()
}

var _ service.EmailChangeMetricsPort = PrometheusEmailChangeMetrics{}
