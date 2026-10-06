package service

// PwdResetMetricsPort telemetría CU-CRED-01 (T-05). Sin SDK directo (DIP).
type PwdResetMetricsPort interface {
	IncReset(op, result string)
	ObserveResetDuration(op string, seconds float64)
	IncHibpFallback()
	IncMismatch(risk string)
	IncResetFallback(reason string)
}

// NoopPwdResetMetrics default sin telemetría.
type NoopPwdResetMetrics struct{}

func (NoopPwdResetMetrics) IncReset(string, string)              {}
func (NoopPwdResetMetrics) ObserveResetDuration(string, float64) {}
func (NoopPwdResetMetrics) IncHibpFallback()                     {}
func (NoopPwdResetMetrics) IncMismatch(string)                   {}
func (NoopPwdResetMetrics) IncResetFallback(string)              {}
