package service

// PlessMetricsPort telemetría CU-AUTH-05 (T-05). Sin SDK directo (DIP).
type PlessMetricsPort interface {
	IncPless(op, result string)
	ObservePlessDuration(op string, seconds float64)
	IncMismatch(risk string)
	IncPlessFallback(reason string)
}

// NoopPlessMetrics default sin telemetría.
type NoopPlessMetrics struct{}

func (NoopPlessMetrics) IncPless(string, string)           {}
func (NoopPlessMetrics) ObservePlessDuration(string, float64) {}
func (NoopPlessMetrics) IncMismatch(string)               {}
func (NoopPlessMetrics) IncPlessFallback(string)          {}
