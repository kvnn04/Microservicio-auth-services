package user

import "context"

// ProbeOutcome es el desenlace INTERNO de una sonda de unicidad.
// Nunca se expone al cliente (siempre respuesta genérica).
type ProbeOutcome string

const (
	ProbeUnique           ProbeOutcome = "unique"
	ProbeShadowDuplicate  ProbeOutcome = "shadow_duplicate"
	ProbeThrottledNotify  ProbeOutcome = "throttled_notify"
	ProbeError            ProbeOutcome = "error"
)

// UniquenessResult resume una sonda (solo hashes, jamás email plano).
type UniquenessResult struct {
	NormalizedEmail string
	EmailHash       string
	Domain          string
	Found           bool
	UserID          string
	NotifyAllowed   bool
}

// DecideProbe mapea (found, notifyAllowed) al outcome interno.
func DecideProbe(found, notifyAllowed bool) ProbeOutcome {
	if !found {
		return ProbeUnique
	}
	if notifyAllowed {
		return ProbeShadowDuplicate
	}
	return ProbeThrottledNotify
}

// ShouldNotify indica si encolar el email al dueño (solo found + throttle OK).
func ShouldNotify(found, throttleAllowed bool) bool {
	return found && throttleAllowed
}

// UniquenessChecker sondea existencia (SELECT id,status). ErrInfra si DB cae.
type UniquenessChecker interface {
	Probe(ctx context.Context, normalizedEmail string) (found bool, userID *string, err error)
}

// NotifyThrottle limita el email al dueño: 1/hora + 3/día por email_hash.
// Fail-open: si el store cae retorna allowed=true (una vez) + métrica fallback.
type NotifyThrottle interface {
	AllowOwnerNotify(ctx context.Context, emailHash string) (allowed bool, err error)
}
