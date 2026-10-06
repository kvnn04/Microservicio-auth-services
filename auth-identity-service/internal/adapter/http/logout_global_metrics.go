package http

import (
	"auth-identity-service/internal/domain/auth"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	logoutGlobalTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "logout_global_total", Help: "Cortes globales por resultado (ok|rate_limited|invalid|error).",
	}, []string{"result"})
	logoutGlobalDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "logout_global_duration_seconds", Help: "Duración del corte global (Tx + sweep).",
		Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5},
	})
	// Buckets del spec §6: 1,2,5,10,20 (+Inf implícito para >20).
	sessionsRevokedCount = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "sessions_revoked_count", Help: "Sesiones revocadas por corte global.",
		Buckets: []float64{1, 2, 5, 10, 20},
	})
)

// PrometheusGlobalMetrics implementa auth.GlobalLogoutMetrics (CU-SES-02 T-05).
type PrometheusGlobalMetrics struct{}

func NewPrometheusGlobalMetrics() *PrometheusGlobalMetrics {
	return &PrometheusGlobalMetrics{}
}

func (PrometheusGlobalMetrics) IncGlobal(result string) {
	logoutGlobalTotal.WithLabelValues(result).Inc()
}
func (PrometheusGlobalMetrics) ObserveGlobalDuration(v float64) {
	logoutGlobalDuration.Observe(v)
}
func (PrometheusGlobalMetrics) ObserveSessionsRevoked(n int) {
	sessionsRevokedCount.Observe(float64(n))
}

var _ auth.GlobalLogoutMetrics = PrometheusGlobalMetrics{}
