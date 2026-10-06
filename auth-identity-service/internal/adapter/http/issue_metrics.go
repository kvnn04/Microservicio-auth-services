package http

import (
	"auth-identity-service/internal/domain/auth"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	tokensIssued = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "tokens_issued_total", Help: "Pares Access+Refresh emitidos por método/amr.",
	}, []string{"method", "amr"})
	issueDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "token_issue_duration_seconds", Help: "Duración del Issue.",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
	})
	sessionsEvicted = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sessions_evicted_total", Help: "Sesiones evictadas por razón.",
	}, []string{"reason"})
	issueRedisFallback = promauto.NewCounter(prometheus.CounterOpts{
		Name: "issue_redis_fallback_total", Help: "Issues entregados vía PG por Redis down.",
	})
	issueInfraErr = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "issue_infra_errors_total", Help: "Errores infra en Issue por operación.",
	}, []string{"op"})
	sessionsActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "sessions_active_gauge", Help: "Sesiones activas (worker 1min COUNT).",
	})
)

// PrometheusIssueMetrics implementa auth.SessionIssueMetrics (CU-AUTH-04 T-05).
type PrometheusIssueMetrics struct{}

func NewPrometheusIssueMetrics() *PrometheusIssueMetrics { return &PrometheusIssueMetrics{} }

func (PrometheusIssueMetrics) IncIssued(method, amr string) {
	tokensIssued.WithLabelValues(method, amr).Inc()
}
func (PrometheusIssueMetrics) ObserveIssueDuration(v float64) { issueDuration.Observe(v) }
func (PrometheusIssueMetrics) IncEvicted(reason string) {
	sessionsEvicted.WithLabelValues(reason).Inc()
}
func (PrometheusIssueMetrics) IncRedisFallback() { issueRedisFallback.Inc() }
func (PrometheusIssueMetrics) IncInfraError(op string) {
	issueInfraErr.WithLabelValues(op).Inc()
}

// SetSessionsActive la actualiza el worker (COUNT sessions 1min).
func SetSessionsActive(n float64) { sessionsActive.Set(n) }

var _ auth.SessionIssueMetrics = PrometheusIssueMetrics{}
