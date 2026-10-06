package http

import (
	"auth-identity-service/internal/service"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	backupTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "backup_total", Help: "Backup codes por op y resultado.",
	}, []string{"op", "result"})
	backupRemaining = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "backup_remaining_gauge", Help: "Backups restantes por bucket.",
	}, []string{"bucket"})
)

// PrometheusBackupMetrics implementa service.BackupMetricsPort.
type PrometheusBackupMetrics struct{}

func NewPrometheusBackupMetrics() *PrometheusBackupMetrics {
	return &PrometheusBackupMetrics{}
}

func (PrometheusBackupMetrics) IncBackup(op, r string) { backupTotal.WithLabelValues(op, r).Inc() }
func (PrometheusBackupMetrics) SetRemaining(remaining int) {
	backupRemaining.WithLabelValues(remainingBucket(remaining)).Set(float64(remaining))
}

func remainingBucket(n int) string {
	switch {
	case n <= 0:
		return "0"
	case n <= 2:
		return "1-2"
	default:
		return "3-10"
	}
}

var _ service.BackupMetricsPort = PrometheusBackupMetrics{}
