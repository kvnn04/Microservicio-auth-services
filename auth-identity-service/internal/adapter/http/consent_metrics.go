package http

import (
	"auth-identity-service/internal/service"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	consentRecorded = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "consent_recorded_total", Help: "Consentimientos por doc y fuente.",
	}, []string{"doc_type", "source"})
	consentRejected = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "consent_rejected_total", Help: "Rechazos por motivo.",
	}, []string{"reason"})
	consentOutdated = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "consent_outdated_total", Help: "Versiones viejas por doc.",
	}, []string{"doc_type"})
	legalVersionInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "legal_active_version_info", Help: "Versión activa (=1).",
	}, []string{"doc_type", "version"})
)

// PrometheusConsentMetrics implementa service.ConsentMetricsPort.
type PrometheusConsentMetrics struct{}

func NewPrometheusConsentMetrics() *PrometheusConsentMetrics {
	return &PrometheusConsentMetrics{}
}

func (PrometheusConsentMetrics) IncConsentRecorded(doc, source string) {
	consentRecorded.WithLabelValues(doc, source).Inc()
}
func (PrometheusConsentMetrics) IncConsentRejected(reason string) {
	consentRejected.WithLabelValues(reason).Inc()
}
func (PrometheusConsentMetrics) IncConsentOutdated(doc string) {
	consentOutdated.WithLabelValues(doc).Inc()
}

// SetActiveVersion fija el gauge de versión activa (llamado en GET y servicio).
func SetActiveVersion(docType, version string) {
	for _, v := range []string{version} {
		legalVersionInfo.WithLabelValues(docType, v).Set(1)
	}
}

var _ service.ConsentMetricsPort = PrometheusConsentMetrics{}
