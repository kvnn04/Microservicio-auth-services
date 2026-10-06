package http

import (
	"auth-identity-service/internal/service"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	pwdResetTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "password_reset_total", Help: "Password reset por operación y resultado.",
	}, []string{"op", "result"})
	pwdResetDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "password_reset_duration_seconds", Help: "Duración password reset.",
		Buckets: []float64{0.05, 0.1, 0.2, 0.5, 1, 2, 5},
	}, []string{"op"})
	pwdResetMismatch = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pwdreset_mismatch_total", Help: "Confirms high-risk.",
	}, []string{"risk"})
	pwdResetHibp = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pwdreset_hibp_fallback_total", Help: "Fallbacks HIBP a lista local.",
	})
	pwdResetFallback = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pwdreset_redis_fallback_total", Help: "Fallbacks Redis→Postgres.",
	}, []string{"reason"})
)

// PrometheusPwdResetMetrics implementa service.PwdResetMetricsPort (CU-CRED-01 T-05).
type PrometheusPwdResetMetrics struct{}

func NewPrometheusPwdResetMetrics() *PrometheusPwdResetMetrics {
	return &PrometheusPwdResetMetrics{}
}

func (PrometheusPwdResetMetrics) IncReset(op, r string) { pwdResetTotal.WithLabelValues(op, r).Inc() }
func (PrometheusPwdResetMetrics) ObserveResetDuration(op string, v float64) {
	pwdResetDuration.WithLabelValues(op).Observe(v)
}
func (PrometheusPwdResetMetrics) IncHibpFallback() { pwdResetHibp.Inc() }
func (PrometheusPwdResetMetrics) IncMismatch(risk string) {
	pwdResetMismatch.WithLabelValues(risk).Inc()
}
func (PrometheusPwdResetMetrics) IncResetFallback(reason string) {
	pwdResetFallback.WithLabelValues(reason).Inc()
}

var _ service.PwdResetMetricsPort = PrometheusPwdResetMetrics{}
