package http

import (
	"auth-identity-service/internal/domain/auth"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	logoutTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "logout_total", Help: "Logouts por resultado (ok|already|invalid|rate_limited|error).",
	}, []string{"result"})
	logoutDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "logout_duration_seconds", Help: "Duración del logout (sin Argon2).",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
	})
	logoutDenylistSize = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "logout_denylist_size_gauge", Help: "Tamaño aprox denylist jti:* (muestreo DBSIZE).",
	})
)

// PrometheusLogoutMetrics implementa auth.LogoutMetrics (CU-SES-01 T-05).
type PrometheusLogoutMetrics struct{}

func NewPrometheusLogoutMetrics() *PrometheusLogoutMetrics {
	return &PrometheusLogoutMetrics{}
}

func (PrometheusLogoutMetrics) IncLogout(result string) {
	logoutTotal.WithLabelValues(result).Inc()
}
func (PrometheusLogoutMetrics) ObserveLogoutDuration(v float64) {
	logoutDuration.Observe(v)
}
func (PrometheusLogoutMetrics) SetDenylistSize(n float64) {
	logoutDenylistSize.Set(n)
}

var _ auth.LogoutMetrics = PrometheusLogoutMetrics{}
