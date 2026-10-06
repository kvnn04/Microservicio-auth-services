package security

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// HybridVerifier verifica Access enterprise Ed25519 y legacy HS256 (transición).
// - EdDSA/kid → Ed25519Signer.Verify (aud=api, TTL 900s, kid estricto).
// - HS256/sin kid → legacy SessionIssuer.VerifyBusiness (aud ausente).
// Rechaza pre-tokens MFA (aud=mfa-challenge) en ambos casos.
type HybridVerifier struct {
	ed  *Ed25519Signer
	leg *SessionIssuer
}

func NewHybridVerifier(ed *Ed25519Signer, leg *SessionIssuer) *HybridVerifier {
	return &HybridVerifier{ed: ed, leg: leg}
}

// VerifyBusiness implementa la interfaz del middleware (misma firma legacy).
func (h *HybridVerifier) VerifyBusiness(token string) (*VerifiedSession, error) {
	// Detecta alg por header sin verificar (solo enrutamiento; la firma se
	// verifica después en cada rama con ConstantTime/ed25519).
	alg, _ := peekAlgAud(token)
	if alg == "EdDSA" {
		if h.ed == nil {
			return nil, errNoVerifier()
		}
		claims, err := h.ed.Verify(token)
		if err != nil {
			return nil, err
		}
		// Negocio solo acepta aud=api (rechaza mfa-challenge y otros).
		if claims.Aud != "api" {
			return nil, errNonBusiness()
		}
		return &VerifiedSession{
			UserID:   claims.Sub,
			AuthTime: unixToTime(claims.AuthTime),
			Expires:  unixToTime(claims.Exp),
		}, nil
	}
	// Fallback legacy HS256 (tests + transición).
	if h.leg == nil {
		return nil, errNoVerifier()
	}
	return h.leg.VerifyBusiness(token)
}

func peekAlgAud(token string) (alg, aud string) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", ""
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", ""
	}
	var h struct {
		Alg string `json:"alg"`
	}
	_ = json.Unmarshal(hb, &h)
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return h.Alg, ""
	}
	var p struct {
		Aud any `json:"aud"`
	}
	if err := json.Unmarshal(pb, &p); err != nil {
		return h.Alg, ""
	}
	switch a := p.Aud.(type) {
	case string:
		return h.Alg, a
	default:
		return h.Alg, ""
	}
}

func errNoVerifier() error {
	return errBusiness("no verifier")
}

func errNonBusiness() error {
	return errBusiness("non-business audience")
}

func errBusiness(msg string) error {
	return &businessError{msg: msg}
}

func unixToTime(u int64) time.Time {
	return time.Unix(u, 0).UTC()
}

type businessError struct{ msg string }

func (e *businessError) Error() string { return e.msg }
