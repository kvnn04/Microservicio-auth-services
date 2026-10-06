package http

import (
	"auth-identity-service/internal/service"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	fedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "federated_registration_total",
		Help: "Registros federados por proveedor y resultado.",
	}, []string{"provider", "result"})
	fedIDPLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "federated_idp_latency_seconds", Help: "Latencia IdP por operación.",
		Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5},
	}, []string{"op"})
	fedCollisions = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "federated_collisions_total", Help: "Colisiones email federadas.",
	}, []string{"provider"})
	fedDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "federated_callback_duration_seconds", Help: "Duración del callback.",
		Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5},
	})
)

// PrometheusFederatedMetrics implementa service.FederatedMetricsPort.
type PrometheusFederatedMetrics struct{}

func NewPrometheusFederatedMetrics() *PrometheusFederatedMetrics {
	return &PrometheusFederatedMetrics{}
}

func (PrometheusFederatedMetrics) IncFederated(p, r string) { fedTotal.WithLabelValues(p, r).Inc() }
func (PrometheusFederatedMetrics) ObserveFederatedDuration(v float64) {
	fedDuration.Observe(v)
}
func (PrometheusFederatedMetrics) ObserveIDPLatency(op string, v float64) {
	fedIDPLatency.WithLabelValues(op).Observe(v)
}
func (PrometheusFederatedMetrics) IncCollision(p string) { fedCollisions.WithLabelValues(p).Inc() }

var _ service.FederatedMetricsPort = PrometheusFederatedMetrics{}
