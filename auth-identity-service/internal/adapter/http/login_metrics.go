package http

import (
	"auth-identity-service/internal/service"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	loginTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "login_total", Help: "Logins por resultado.",
	}, []string{"result"})
	loginDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "login_duration_seconds", Help: "Duración del login.",
		Buckets: []float64{0.05, 0.1, 0.2, 0.5, 1, 2, 5},
	})
	loginFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "login_failures_total", Help: "Fallos internos (privado).",
	}, []string{"reason_internal"})
	loginLocks = promauto.NewCounter(prometheus.CounterOpts{
		Name: "login_locks_total", Help: "Bloqueos creados.",
	})
	loginLockEmails = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "login_lock_emails_total", Help: "Emails de bloqueo por throttle.",
	}, []string{"throttled"})
)

// PrometheusLoginMetrics implementa service.LoginMetricsPort.
type PrometheusLoginMetrics struct{}

func NewPrometheusLoginMetrics() *PrometheusLoginMetrics { return &PrometheusLoginMetrics{} }

func (PrometheusLoginMetrics) IncLogin(r string)            { loginTotal.WithLabelValues(r).Inc() }
func (PrometheusLoginMetrics) ObserveLoginDuration(v float64) { loginDuration.Observe(v) }
func (PrometheusLoginMetrics) IncLoginFailure(r string)     { loginFailures.WithLabelValues(r).Inc() }
func (PrometheusLoginMetrics) IncLoginLock()                { loginLocks.Inc() }
func (PrometheusLoginMetrics) IncLoginLockEmail(t bool) {
	s := "false"
	if t {
		s = "true"
	}
	loginLockEmails.WithLabelValues(s).Inc()
}

var _ service.LoginMetricsPort = PrometheusLoginMetrics{}
