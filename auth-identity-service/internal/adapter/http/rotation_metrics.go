package http

import (
	"auth-identity-service/internal/domain/auth"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	rotationTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rotation_total",
		Help: "Rotaciones por resultado (ok|grace_idempotent|concurrent|reuse|expired|revoked|invalid|rate_limited|error).",
	}, []string{"result"})
	rotationDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "rotation_duration_seconds", Help: "Duración del rotate (sin Argon2).",
		Buckets: []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2},
	})
	// P1: el pager/ops alerta sobre esta señal (severidad crítica).
	reuseDetectedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "reuse_detected_total", Help: "Reusos confirmados (robo) por severidad.",
	}, []string{"severity"})
	concurrent409Total = promauto.NewCounter(prometheus.CounterOpts{
		Name: "concurrent_409_total", Help: "Races legítimos (409 reintentable, sin alarma).",
	})
)

// PrometheusRotationMetrics implementa auth.RotationMetrics (CU-SES-04 T-05).
type PrometheusRotationMetrics struct{}

func NewPrometheusRotationMetrics() *PrometheusRotationMetrics {
	return &PrometheusRotationMetrics{}
}

func (PrometheusRotationMetrics) IncRotation(result string) {
	rotationTotal.WithLabelValues(result).Inc()
}
func (PrometheusRotationMetrics) ObserveRotationDuration(v float64) {
	rotationDuration.Observe(v)
}
func (PrometheusRotationMetrics) IncReuseDetected() {
	reuseDetectedTotal.WithLabelValues("critical").Inc()
}
func (PrometheusRotationMetrics) IncConcurrent() { concurrent409Total.Inc() }

var _ auth.RotationMetrics = PrometheusRotationMetrics{}
