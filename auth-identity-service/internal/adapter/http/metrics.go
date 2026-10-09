package http

import (
	"auth-identity-service/internal/service"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	regTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "user_registration_total",
		Help: "Total de registros por estado.",
	}, []string{"status"})
	regDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "user_registration_duration_seconds", Help: "Duración del registro.",
		Buckets: []float64{0.05, 0.1, 0.2, 0.5, 1, 2},
	})
	hibpFallback = promauto.NewCounter(prometheus.CounterOpts{
		Name: "hibp_fallback_total", Help: "Fallback HIBP a lista local.",
	})
	// CU-REG-03: métricas INTERNAS anti-enumeración (dashboard privado).
	uniqProbes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "uniqueness_probes_total", Help: "Sondas de unicidad por desenlace.",
	}, []string{"outcome"})
	notifyOwner = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "notify_owner_enqueued_total", Help: "Notify al dueño por throttle.",
	}, []string{"throttled"})
	ipBlocks = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ip_blocks_total", Help: "IPs bloqueadas progresivamente.",
	})
	// Fix email inicial (2026-10-07): distingue onboarding de resends.
	initialEmailTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "initial_verification_email_total", Help: "Email inicial de verificación por resultado.",
	}, []string{"result"})
)

// PrometheusMetrics implementa service.MetricsPort.
type PrometheusMetrics struct{}

func NewPrometheusMetrics() *PrometheusMetrics { return &PrometheusMetrics{} }
func (PrometheusMetrics) IncRegistration(s string)               { regTotal.WithLabelValues(s).Inc() }
func (PrometheusMetrics) ObserveRegistrationDuration(v float64)  { regDuration.Observe(v) }
func (PrometheusMetrics) IncHibpFallback()                       { hibpFallback.Inc() }
func (PrometheusMetrics) IncUniquenessProbe(o string)            { uniqProbes.WithLabelValues(o).Inc() }
func (PrometheusMetrics) IncNotifyOwner(t bool) {
	s := "false"
	if t {
		s = "true"
	}
	notifyOwner.WithLabelValues(s).Inc()
}
func (PrometheusMetrics) IncIPBlocked() { ipBlocks.Inc() }
func (PrometheusMetrics) IncInitialEmail(r string) {
	initialEmailTotal.WithLabelValues(r).Inc()
}

// BlockCounter adapta IncIPBlocked para el middleware (sin importar service).
type BlockCounter struct{ M *PrometheusMetrics }

func (b BlockCounter) IncIPBlocked() {
	if b.M != nil {
		b.M.IncIPBlocked()
	} else {
		ipBlocks.Inc()
	}
}

var _ service.MetricsPort = PrometheusMetrics{}
