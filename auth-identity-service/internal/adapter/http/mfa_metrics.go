package http

import (
	"auth-identity-service/internal/service"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	mfaTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mfa_total", Help: "MFA por op y resultado.",
	}, []string{"op", "result"})
	mfaVerifyDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "mfa_verify_duration_seconds", Help: "Duración del verify.",
		Buckets: []float64{0.02, 0.05, 0.1, 0.25, 0.5, 1, 2},
	})
	mfaBurned = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mfa_challenges_burned_total", Help: "Challenges quemados.",
	}, []string{"reason"})
	mfaReplay = promauto.NewCounter(prometheus.CounterOpts{
		Name: "mfa_replay_blocked_total", Help: "Replays bloqueados.",
	})
)

// PrometheusMFAMetrics implementa service.MFAMetricsPort.
type PrometheusMFAMetrics struct{}

func NewPrometheusMFAMetrics() *PrometheusMFAMetrics { return &PrometheusMFAMetrics{} }

func (PrometheusMFAMetrics) IncMFA(op, r string) { mfaTotal.WithLabelValues(op, r).Inc() }
func (PrometheusMFAMetrics) ObserveVerifyDuration(v float64) {
	mfaVerifyDuration.Observe(v)
}
func (PrometheusMFAMetrics) IncChallengeBurned(r string) { mfaBurned.WithLabelValues(r).Inc() }
func (PrometheusMFAMetrics) IncReplayBlocked()           { mfaReplay.Inc() }

var _ service.MFAMetricsPort = PrometheusMFAMetrics{}
