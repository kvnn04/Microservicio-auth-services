package auth

import (
	"time"
)

// Constantes CU-SES-02: revocación masiva ante robo/pérdida.
// Rate anti-loop (Q1): 5/hora por usuario + 20/hora por IP.
const (
	// LogoutGlobalUserLimit cortes por hora y usuario (frena hijack-loop).
	LogoutGlobalUserLimit = 5
	// LogoutGlobalIPLimit cortes por hora e IP.
	LogoutGlobalIPLimit = 20
	// LogoutGlobalRateWindow ventana de rate-limit.
	LogoutGlobalRateWindow = time.Hour
)

// GlobalRevokeResult desenlace del corte total (200 siempre, idempotente).
// Sessions/Families cuentan lo revocado EN ESTE corte (repeat → 0/0);
// ValidAfter es el nuevo punto de corte (monótono, re-bumpeado en repeat).
type GlobalRevokeResult struct {
	Sessions   int
	Families   int
	ValidAfter time.Time
}
