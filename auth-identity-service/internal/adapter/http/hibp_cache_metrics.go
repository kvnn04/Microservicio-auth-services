package http

import (
	"auth-identity-service/internal/adapter/security"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var hibpCacheTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "hibp_cache_total", Help: "Caché HIBP por resultado.",
}, []string{"result"})

// PrometheusHibpCacheMetrics implementa security.CacheMetrics (F-19).
type PrometheusHibpCacheMetrics struct{}

func NewPrometheusHibpCacheMetrics() *PrometheusHibpCacheMetrics {
	return &PrometheusHibpCacheMetrics{}
}

func (PrometheusHibpCacheMetrics) IncHibpCache(r string) { hibpCacheTotal.WithLabelValues(r).Inc() }

var _ security.CacheMetrics = (*PrometheusHibpCacheMetrics)(nil)
