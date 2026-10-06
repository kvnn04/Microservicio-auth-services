package http

import (
	"auth-identity-service/internal/domain/auth"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	sessionsListedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sessions_listed_total", Help: "Listados de sesiones por resultado.",
	}, []string{"result"})
	sessionsListDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "sessions_list_duration_seconds", Help: "Duración del listado.",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
	})
	revokedOneTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "session_revoked_one_total", Help: "Revocaciones selectivas por resultado.",
	}, []string{"result"})
	revokedOneDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "session_revoked_one_duration_seconds", Help: "Duración del revoke-one.",
		Buckets: []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2},
	})
)

// PrometheusSessionsMetrics implementa auth.SessionsMetrics (CU-SES-03 T-05).
type PrometheusSessionsMetrics struct{}

func NewPrometheusSessionsMetrics() *PrometheusSessionsMetrics {
	return &PrometheusSessionsMetrics{}
}

func (PrometheusSessionsMetrics) IncListed(result string) {
	sessionsListedTotal.WithLabelValues(result).Inc()
}
func (PrometheusSessionsMetrics) ObserveListDuration(v float64) {
	sessionsListDuration.Observe(v)
}
func (PrometheusSessionsMetrics) IncRevokedOne(result string) {
	revokedOneTotal.WithLabelValues(result).Inc()
}
func (PrometheusSessionsMetrics) ObserveRevokeOneDuration(v float64) {
	revokedOneDuration.Observe(v)
}

var _ auth.SessionsMetrics = PrometheusSessionsMetrics{}
