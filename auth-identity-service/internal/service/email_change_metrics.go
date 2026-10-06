package service

// EmailChangeMetricsPort telemetría CU-CRED-03 (T-05). Sin SDK directo (DIP).
type EmailChangeMetricsPort interface {
	IncEmailChange(op, result string)
	ObserveEmailChangeDuration(op string, seconds float64)
	IncEmailChangeFallback(reason string)
}

// NoopEmailChangeMetrics default sin telemetría.
type NoopEmailChangeMetrics struct{}

func (NoopEmailChangeMetrics) IncEmailChange(string, string)             {}
func (NoopEmailChangeMetrics) ObserveEmailChangeDuration(string, float64) {}
func (NoopEmailChangeMetrics) IncEmailChangeFallback(string)             {}
