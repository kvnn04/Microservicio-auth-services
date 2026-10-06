package http

import (
	"auth-identity-service/internal/service"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	pwdChangeTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "password_change_total", Help: "Cambios de contraseña por resultado y vía.",
	}, []string{"result", "via"})
	pwdChangeDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "password_change_duration_seconds", Help: "Duración del cambio (incluye Verify×N).",
		Buckets: []float64{0.1, 0.25, 0.5, 1, 2, 5},
	})
	pwdChangeHistoryHits = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pwdchange_history_hits_total", Help: "Nuevas claves encontradas en historial.",
	})
	pwdChangePeersRevoked = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sessions_revoked_peers_total", Help: "Sesiones pares revocadas en cambios.",
	})
	pwdChangeHibp = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pwdchange_hibp_fallback_total", Help: "Fallbacks HIBP a lista local.",
	})
)

// PrometheusChangeMetrics implementa service.ChangeMetricsPort (CU-CRED-02 T-05).
// IncChangeLock reutiliza login_locks_total (mismo contador de cuenta).
type PrometheusChangeMetrics struct{}

func NewPrometheusChangeMetrics() *PrometheusChangeMetrics {
	return &PrometheusChangeMetrics{}
}

func (PrometheusChangeMetrics) IncChange(result, via string) {
	pwdChangeTotal.WithLabelValues(result, via).Inc()
}
func (PrometheusChangeMetrics) ObserveChangeDuration(v float64) { pwdChangeDuration.Observe(v) }
func (PrometheusChangeMetrics) IncHistoryHit()                  { pwdChangeHistoryHits.Inc() }
func (PrometheusChangeMetrics) IncPeersRevoked(n int)           { pwdChangePeersRevoked.Add(float64(n)) }
func (PrometheusChangeMetrics) IncChangeLock()                  { loginLocks.Inc() }
func (PrometheusChangeMetrics) IncHibpFallback()                { pwdChangeHibp.Inc() }

var _ service.ChangeMetricsPort = PrometheusChangeMetrics{}
