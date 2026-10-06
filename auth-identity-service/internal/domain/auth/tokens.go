package auth

import (
	"errors"
	"time"
)

// Constantes CU-AUTH-04 (Q1/Q2/Q5): TTLs, tamaños y límites.
// Access 15min verificable vía JWKS; Refresh 32B opaco, sliding 30d,
// absoluto 90d; máximo 20 sesiones por usuario (LRU).
const (
	AccessTTL          = 15 * time.Minute
	RefreshSlidingTTL  = 30 * 24 * time.Hour
	RefreshAbsoluteTTL = 90 * 24 * time.Hour
	RefreshBytes       = 32
	MaxSessionsPerUser = 20

	DefaultIssuer   = "https://auth.example.com"
	DefaultAudience = "api"
	DefaultScope    = "openid profile api"
	TokenVersion    = 1

	// MaxAccessBytes: Access nunca >8KB (si roles exceden, se trunca a
	// roles_ver + scope mínimo; ver NewAccessClaims).
	MaxAccessBytes = 8 * 1024
	// ClockSkew tolerado en verificación (gateway/middleware).
	ClockSkew = 30 * time.Second
)

// AMR (Authentication Methods Reference) — factores reales usados.
type AMR string

const (
	AMRPassword         AMR = "pwd"
	AMRTOTP             AMR = "totp"
	AMRBackup           AMR = "backup"
	AMRFederatedGoogle  AMR = "federated_google"
	AMROTPEmail         AMR = "otp-email"
)

// Métodos primarios de autenticación (campo Method del request).
const (
	MethodPassword         = "password"
	MethodFederatedGoogle  = "federated_google"
	MethodPasswordlessEmail = "passwordless_email" // CU-AUTH-05: secreto efímero por correo
)

var (
	ErrInvalidSessionRequest = errors.New("invalid session request")
	ErrClaimsTooLarge        = errors.New("claims exceed size limit")
)

// SessionRequest entrada al puerto SessionIssuer (interno, sin HTTP).
// Device lo calcula el llamador (login/MFA/federado: ip/24 + ua).
type SessionRequest struct {
	UserID   string
	Method   string
	AMR      []AMR
	AuthTime time.Time
	Device   Device
	Roles    []string
	RolesVer int
}

// IssuedPair salida del Issue (memoria del request + persistencia).
// RefreshPlain SOLO vive en memoria del request (cookie/body TLS);
// en DB/Redis/logs solo su hash SHA-256.
type IssuedPair struct {
	AccessJWT string
	// RefreshPlain 43ch base64url (32B CSPRNG). Vacío jamás se entrega.
	RefreshPlain string
	SID          string
	JTI          string
	Family       string
	KID          string
	ExpiresAt    time.Time
}

// Session VO persistido (PG sessions + Redis sess:<sid>).
type Session struct {
	SID        string
	UserID     string
	Family     string
	JTI        string
	DeviceHash string
	IPHash     string
	CreatedAt  time.Time
	LastSeen   time.Time
	ExpiresAt  time.Time
}

// RefreshFamily familia rotativa (PG refresh_families + Redis fam:<family>).
type RefreshFamily struct {
	Family      string
	UserID      string
	CurrentHash string
	ParentHash  string
	Counter     int
	AbsoluteExp time.Time
	Revoked     bool
}

// RefreshHash eslabón de la cadena (PG refresh_hashes, PK global).
type RefreshHash struct {
	Hash      string
	Family    string
	Counter   int
	ExpiresAt time.Time
}

// AccessClaims payload mínimo del JWT (sin PII: sub UUID, sin email).
type AccessClaims struct {
	Iss      string   `json:"iss"`
	Aud      string   `json:"aud"`
	Sub      string   `json:"sub"`
	SID      string   `json:"sid"`
	JTI      string   `json:"jti"`
	Iat      int64    `json:"iat"`
	Exp      int64    `json:"exp"`
	AuthTime int64    `json:"auth_time"`
	AMR      []string `json:"amr"`
	Scope    string   `json:"scope"`
	Roles    []string `json:"roles"`
	RolesVer int      `json:"roles_ver"`
	TokenVer int      `json:"token_ver"`
}

// ValidateRequest verifica forma del request (puro, sin I/O).
// userACTIVE se verifica en el servicio (vía Users o confianza en llamador);
// aquí solo forma: IDs, method/amr conocidos, device no vacío.
func (r SessionRequest) ValidateRequest(now time.Time) error {
	if r.UserID == "" {
		return ErrInvalidSessionRequest
	}
	if r.Method != MethodPassword && r.Method != MethodFederatedGoogle && r.Method != MethodPasswordlessEmail {
		return ErrInvalidSessionRequest
	}
	if len(r.AMR) == 0 || len(r.AMR) > 4 {
		return ErrInvalidSessionRequest
	}
	for _, a := range r.AMR {
		switch a {
		case AMRPassword, AMRTOTP, AMRBackup, AMRFederatedGoogle, AMROTPEmail:
		default:
			return ErrInvalidSessionRequest
		}
	}
	// Coherencia method/amr: password exige pwd; federated exige federated_google;
	// passwordless_email exige otp-email (CU-AUTH-05).
	hasPwd := false
	hasFed := false
	hasOTPEmail := false
	for _, a := range r.AMR {
		if a == AMRPassword {
			hasPwd = true
		}
		if a == AMRFederatedGoogle {
			hasFed = true
		}
		if a == AMROTPEmail {
			hasOTPEmail = true
		}
	}
	if r.Method == MethodPassword && !hasPwd {
		return ErrInvalidSessionRequest
	}
	if r.Method == MethodFederatedGoogle && !hasFed {
		return ErrInvalidSessionRequest
	}
	if r.Method == MethodPasswordlessEmail && !hasOTPEmail {
		return ErrInvalidSessionRequest
	}
	if r.Device.IPHash == "" || r.Device.UAHash == "" {
		return ErrInvalidSessionRequest
	}
	if r.AuthTime.IsZero() {
		return ErrInvalidSessionRequest
	}
	// auth_time no futuro (+skew) ni anterior a 5min del Issue (login completo).
	if r.AuthTime.After(now.Add(ClockSkew)) {
		return ErrInvalidSessionRequest
	}
	_ = now
	return nil
}

// NewAccessClaims construye claims con TTL exacto 900s y validación.
// roles nil → ["user"]; si el JWT serializado excedería 4KB de roles,
// el llamador debe truncar (aquí solo se valida longitud total razonable).
func NewAccessClaims(iss, aud, sub, sid, jti string, authTime time.Time, amr []AMR, roles []string, rolesVer int, now time.Time) (AccessClaims, error) {
	if iss == "" {
		iss = DefaultIssuer
	}
	if aud == "" {
		aud = DefaultAudience
	}
	if sub == "" || sid == "" || jti == "" {
		return AccessClaims{}, ErrInvalidSessionRequest
	}
	if len(amr) == 0 {
		return AccessClaims{}, ErrInvalidSessionRequest
	}
	amrStr := make([]string, 0, len(amr))
	for _, a := range amr {
		switch a {
		case AMRPassword, AMRTOTP, AMRBackup, AMRFederatedGoogle, AMROTPEmail:
			amrStr = append(amrStr, string(a))
		default:
			return AccessClaims{}, ErrInvalidSessionRequest
		}
	}
	if roles == nil {
		roles = []string{"user"}
	}
	if len(roles) > 64 {
		return AccessClaims{}, ErrClaimsTooLarge
	}
	iat := now.Unix()
	exp := now.Add(AccessTTL).Unix()
	if exp-iat != int64((AccessTTL/time.Second)) {
		return AccessClaims{}, ErrInvalidSessionRequest
	}
	return AccessClaims{
		Iss: iss, Aud: aud, Sub: sub, SID: sid, JTI: jti,
		Iat: iat, Exp: exp, AuthTime: authTime.Unix(),
		AMR: amrStr, Scope: DefaultScope, Roles: roles,
		RolesVer: rolesVer, TokenVer: TokenVersion,
	}, nil
}
