package service

// StepUpMetricsPort telemetría CU-AUTH-06 (T-05). Sin SDK directo (DIP).
type StepUpMetricsPort interface {
	IncStepUp(op, result string)
	ObserveStepUpDuration(op string, seconds float64)
	IncReuseBlocked()
}

// NoopStepUpMetrics default sin telemetría.
type NoopStepUpMetrics struct{}

func (NoopStepUpMetrics) IncStepUp(string, string)              {}
func (NoopStepUpMetrics) ObserveStepUpDuration(string, float64) {}
func (NoopStepUpMetrics) IncReuseBlocked()                      {}
