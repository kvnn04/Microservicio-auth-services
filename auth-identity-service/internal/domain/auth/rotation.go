package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
	"time"
)

// Constantes CU-SES-04: rotación single-use con gracia anti-retry.
// Gracia 10s + idempotencia RequestID 60s + anti-flapping 3/10s.
const (
	// GraceWindow: parent presentado dentro de la ventana post-rotate
	// (mismo device) → 409 reintentable, no global (sin falsos retry).
	GraceWindow = 10 * time.Second
	// IdempotencyWindow: mismo X-Request-ID devuelve el par guardado.
	IdempotencyWindow = 60 * time.Second
	// ConcurrentLimit: a partir del 4º evento concurrente con el mismo
	// viejo en la ventana → se escala a global (probable robo real).
	ConcurrentLimit = 3
	// ConcurrentWindow ventana del contador anti-flapping.
	ConcurrentWindow = 10 * time.Second
	// RefreshRateIP tope anti-ruido por IP (el secreto es 256-bit;
	// adivinarlo es inviable: el rate no es anti-adivinanza).
	RefreshRateIP = 30
	// RefreshRateFam tope por hash presentado (de facto por family-chain).
	RefreshRateFam = 10
	// RefreshRateWindow ventana de ambos buckets.
	RefreshRateWindow = time.Minute
	// RefreshBodyMax 4KB (contracts §1).
	RefreshBodyMax = 4 << 10
)

// RotateDecision desenlace puro de la máquina de estados (sin I/O).
type RotateDecision string

const (
	// DecideRotateCurrent el presentado es el vigente → rotar (CAS).
	DecideRotateCurrent RotateDecision = "rotate"
	// DecideConcurrent parent en gracia + mismo device (+flaps<4):
	// 409 reintentable con algoritmo cliente (re-lee jar). Sin alarma.
	DecideConcurrent RotateDecision = "concurrent"
	// DecideReuse cualquier otro consumido / mismatch / flaps≥4:
	// robo → GLOBAL + P1 + email crítico.
	DecideReuse RotateDecision = "reuse"
)

// DecideRotate clasifica el hash presentado contra la cadena.
// flaps = eventos concurrentes con este viejo en la ventana (post-INCR);
// con flaps>ConcurrentLimit (4º) escala a global aunque parezca race.
func DecideRotate(isCurrent, isParent, withinGrace, sameDevice bool, flaps int) RotateDecision {
	if isCurrent {
		return DecideRotateCurrent
	}
	if isParent && withinGrace && sameDevice {
		if flaps > ConcurrentLimit {
			return DecideReuse
		}
		return DecideConcurrent
	}
	return DecideReuse
}

// DeviceMatch verifica mismo-device entre el presentado (IP/UA crudos del
// request actual) y el device_hash guardado al Issue.
//
// Robusto por diseño: prueba los esquemas históricos de huellas (login/mfa/
// federado usan H(H(ip+"/24")+H(ua)); passwordless usa H(H(MaskIP24(ip))+
// H(trim(ua)))) sobre la IP cruda y sin-puerto, porque el de emisión pudo
// calcularse con cualquiera según el flujo + con/sin puerto según proxy.
// Cualquier coincidencia vale (sha256 hace infalsificable el OR).
// Límite conocido: gemelos NAT con UA idéntica matchean — el backstop
// anti-flapping (global al 4º) los contiene de todos modos.
func DeviceMatch(stored, ip, ua string) bool {
	if stored == "" {
		return false
	}
	ips := []string{ip, stripPort(ip)}
	uastrs := []string{ua, strings.TrimSpace(ua)}
	for _, cip := range ips {
		for _, cua := range uastrs {
			if fingerprintS1(cip, cua) == stored {
				return true
			}
			if fingerprintS2(cip, cua) == stored {
				return true
			}
		}
	}
	return false
}

// fingerprintS1 esquema login/mfa/federated: H(H(ip+"/24") + H(ua)).
func fingerprintS1(ip, ua string) string {
	ih := sha256.Sum256([]byte(ip + "/24"))
	uh := sha256.Sum256([]byte(ua))
	sum := sha256.Sum256([]byte(hex.EncodeToString(ih[:]) + hex.EncodeToString(uh[:])))
	return hex.EncodeToString(sum[:])
}

// fingerprintS2 esquema passwordless: H(H(MaskIP24(ip)) + H(trim(ua))).
func fingerprintS2(ip, ua string) string {
	ih := sha256.Sum256([]byte(MaskIP24(ip)))
	uh := sha256.Sum256([]byte(strings.TrimSpace(ua)))
	sum := sha256.Sum256([]byte(hex.EncodeToString(ih[:]) + hex.EncodeToString(uh[:])))
	return hex.EncodeToString(sum[:])
}

// stripPort quita :puerto (directas sin proxy) para matchear formas con y
// sin puerto. Las familias nuevas heredan el esquema de su flujo de Issue
// (S1/S2 según login/mfa/federated/pless); el matcher cubre ambos siempre.
func stripPort(s string) string {
	if h, _, err := net.SplitHostPort(strings.TrimSpace(s)); err == nil {
		return h
	}
	return strings.TrimSpace(s)
}
