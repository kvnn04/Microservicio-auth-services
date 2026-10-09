package user

// VerificationMail material efímero para el email de verificación inicial
// (fix 2026-10-07 CU-REG-01 F-16; mismo formato que el resend CU-REG-02).
// Los planos viven SOLO en memoria del request: el adapter persiste hashes
// (token + OTP en verification_tokens) y encola el email en la MISMA Tx;
// nada plano sale de este paquete hacia logs, eventos Kafka o respuestas
// (el email va a email_queue interna).
type VerificationMail struct {
	TokenPlain, TokenHash string
	OTPPlain, OTPHash     string
}
