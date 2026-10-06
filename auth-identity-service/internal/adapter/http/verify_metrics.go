package http

import (
	"auth-identity-service/internal/service"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	verifyTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "email_verification_total",
		Help: "Total de verificaciones por resultado y método.",
	}, []string{"result", "method"})
	verifyDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "email_verification_duration_seconds", Help: "Duración de verificación.",
		Buckets: []float64{0.05, 0.1, 0.2, 0.5, 1, 2},
	})
	resendsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "verification_resends_total", Help: "Reenvíos por desenlace.",
	}, []string{"outcome"})
	attemptsBurned = promauto.NewCounter(prometheus.CounterOpts{
		Name: "verification_attempts_burned_total", Help: "Secretos quemados por 3 intentos.",
	})
	redisFallback = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "verify_redis_fallback_total", Help: "Fallbacks Redis→Postgres.",
	}, []string{"reason"})
)

// PrometheusVerifyMetrics implementa service.VerifyMetricsPort.
type PrometheusVerifyMetrics struct{}

func NewPrometheusVerifyMetrics() *PrometheusVerifyMetrics {
	return &PrometheusVerifyMetrics{}
}

func (PrometheusVerifyMetrics) IncVerification(result, method string) {
	verifyTotal.WithLabelValues(result, method).Inc()
}
func (PrometheusVerifyMetrics) ObserveVerificationDuration(v float64) {
	verifyDuration.Observe(v)
}
func (PrometheusVerifyMetrics) IncResend(outcome string) { resendsTotal.WithLabelValues(outcome).Inc() }
func (PrometheusVerifyMetrics) IncAttemptsBurned()       { attemptsBurned.Inc() }
func (PrometheusVerifyMetrics) IncRedisFallback(reason string) {
	redisFallback.WithLabelValues(reason).Inc()
}

var _ service.VerifyMetricsPort = PrometheusVerifyMetrics{}
