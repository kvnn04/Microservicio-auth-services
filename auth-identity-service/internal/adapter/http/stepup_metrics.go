package http

import (
	"auth-identity-service/internal/service"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	stepUpTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "step_up_total", Help: "Step-up por operación y resultado.",
	}, []string{"op", "result"})
	stepUpDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "step_up_duration_seconds", Help: "Duración step-up.",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2},
	}, []string{"op"})
	stepUpReuseBlocked = promauto.NewCounter(prometheus.CounterOpts{
		Name: "step_up_reuse_blocked_total", Help: "Reusos de jti bloqueados.",
	})
)

// PrometheusStepUpMetrics implementa service.StepUpMetricsPort (CU-AUTH-06 T-05).
type PrometheusStepUpMetrics struct{}

func NewPrometheusStepUpMetrics() *PrometheusStepUpMetrics { return &PrometheusStepUpMetrics{} }

func (PrometheusStepUpMetrics) IncStepUp(op, r string) { stepUpTotal.WithLabelValues(op, r).Inc() }
func (PrometheusStepUpMetrics) ObserveStepUpDuration(op string, v float64) {
	stepUpDuration.WithLabelValues(op).Observe(v)
}
func (PrometheusStepUpMetrics) IncReuseBlocked() { stepUpReuseBlocked.Inc() }

var _ service.StepUpMetricsPort = PrometheusStepUpMetrics{}
