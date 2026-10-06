package http

import (
	"auth-identity-service/internal/service"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	linkTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "federated_link_total", Help: "Link/unlink por proveedor, op y resultado.",
	}, []string{"provider", "op", "result"})
	lastFactorBlocked = promauto.NewCounter(prometheus.CounterOpts{
		Name: "unlink_last_factor_blocked_total", Help: "Unlinks bloqueados por último factor.",
	})
	linkStateFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "link_state_failures_total", Help: "Fallos de estado link.",
	}, []string{"reason"})
)

// PrometheusLinkMetrics implementa LinkMetricsPort.
type PrometheusLinkMetrics struct{}

func NewPrometheusLinkMetrics() *PrometheusLinkMetrics { return &PrometheusLinkMetrics{} }

func (PrometheusLinkMetrics) IncLink(provider, op, result string) {
	linkTotal.WithLabelValues(provider, op, result).Inc()
}
func (PrometheusLinkMetrics) IncLastFactorBlocked() { lastFactorBlocked.Inc() }
func (PrometheusLinkMetrics) IncLinkStateFailure(reason string) {
	linkStateFailures.WithLabelValues(reason).Inc()
}

var _ service.LinkMetricsPort = PrometheusLinkMetrics{}
