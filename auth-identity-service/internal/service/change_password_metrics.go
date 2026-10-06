package service

// ChangeMetricsPort telemetría CU-CRED-02 (T-05). Sin SDK directo (DIP).
type ChangeMetricsPort interface {
	IncChange(result, via string)
	ObserveChangeDuration(seconds float64)
	IncHistoryHit()
	IncPeersRevoked(n int)
	IncChangeLock()
	IncHibpFallback()
}

// NoopChangeMetrics default sin telemetría.
type NoopChangeMetrics struct{}

func (NoopChangeMetrics) IncChange(string, string)      {}
func (NoopChangeMetrics) ObserveChangeDuration(float64) {}
func (NoopChangeMetrics) IncHistoryHit()                {}
func (NoopChangeMetrics) IncPeersRevoked(int)           {}
func (NoopChangeMetrics) IncChangeLock()                {}
func (NoopChangeMetrics) IncHibpFallback()              {}
