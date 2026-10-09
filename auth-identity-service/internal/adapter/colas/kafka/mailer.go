package kafka

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EmailMailer envía la cola durable email_queue vía SMTP (Mailhog local).
// El secreto plano NUNCA va a Kafka: vive solo en esta tabla interna hasta
// ser enviado, luego la fila se marca sent. El relay Kafka no toca este tópico.
//
// Autenticación SMTP (Gmail/relays reales): si smtpUser != "" usa
// smtp.PlainAuth contra el host de smtpAddr. Requiere STARTTLS, o sea
// puerto 587 (NO 465: Go no hace TLS implícito). Sin usuario = anónimo
// (Mailhog/dev). El remitente envelope debe ser dirección pelada.
type EmailMailer struct {
	pool      *pgxpool.Pool
	smtpAddr  string
	smtpUser  string
	smtpPass  string
	from      string
	frontURL  string
}

func NewEmailMailer(pool *pgxpool.Pool, smtpAddr, from string) *EmailMailer {
	return &EmailMailer{pool: pool, smtpAddr: smtpAddr, from: from}
}

// NewEmailMailerWithAuth igual + credenciales SMTP (vault en prod).
func NewEmailMailerWithAuth(pool *pgxpool.Pool, smtpAddr, from, user, pass string) *EmailMailer {
	return &EmailMailer{pool: pool, smtpAddr: smtpAddr, from: from, smtpUser: user, smtpPass: pass}
}

// SetFrontURL configura la base para links login/forgot del notify (CU-REG-03).
func (m *EmailMailer) SetFrontURL(u string) { m.frontURL = u }

// Run loop cada 2s con graceful shutdown vía ctx.
func (m *EmailMailer) Run(ctx context.Context) error {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			_ = m.DrainOnce(ctx, 20)
			_ = m.DrainNotifyOnce(ctx, 20)
		}
	}
}

func (m *EmailMailer) DrainOnce(ctx context.Context, limit int) error {
	if m.smtpAddr == "" {
		return nil // SMTP no configurado: la cola espera (E2E usa Mailhog).
	}
	rows, err := m.pool.Query(ctx, `SELECT id::text, to_email, subject, body_text, attempts
		FROM email_queue WHERE status='pending' ORDER BY created_at ASC LIMIT $1
		FOR UPDATE SKIP LOCKED`, limit)
	if err != nil {
		return err
	}
	type item struct {
		id, to, subject, body string
		attempts              int
	}
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.to, &it.subject, &it.body, &it.attempts); err != nil {
			rows.Close()
			return err
		}
		items = append(items, it)
	}
	rows.Close()
	for _, it := range items {
		if err := m.send(it.to, it.subject, it.body); err != nil {
			_, _ = m.pool.Exec(ctx, `UPDATE email_queue SET attempts=attempts+1,
				status=CASE WHEN attempts+1>25 THEN 'failed' ELSE 'pending' END WHERE id=$1::uuid`, it.id)
			continue
		}
		_, _ = m.pool.Exec(ctx, `UPDATE email_queue SET status='sent', sent_at=now() WHERE id=$1::uuid`, it.id)
	}
	return nil
}

func (m *EmailMailer) send(to, subject, body string) error {
	msg := "From: " + m.from + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n\r\n" + body
	return smtp.SendMail(m.smtpAddr, m.smtpAuth(), m.from, []string{to}, []byte(msg))
}

// smtpAuth devuelve PlainAuth solo si hay usuario configurado (nil = anónimo,
// comportamiento anterior para Mailhog/dev).
func (m *EmailMailer) smtpAuth() smtp.Auth {
	if m.smtpUser == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(m.smtpAddr)
	if err != nil {
		host = m.smtpAddr
	}
	return smtp.PlainAuth("", m.smtpUser, m.smtpPass, host)
}

// RenderVerificationBody plantilla link+OTP (documentada, sin PII en logs).
func RenderVerificationBody(link, otpCode string) string {
	var b strings.Builder
	b.WriteString("Verifica tu cuenta (expira en 15 minutos, un solo uso):\n\n")
	b.WriteString("Enlace: " + link + "\nCodigo: " + otpCode + "\n")
	return b.String()
}

// DrainNotifyOnce procesa security.registration_attempted (CU-REG-03 §4.2):
// claim atómico, lookup del email del dueño por aggregate_id (user_id),
// plantilla con links login/forgot (SIN token), marca sent. El relay Kafka
// no reclama estas filas en dev (sin broker); en prod el evento también viaja
// a Kafka para otros consumidores.
func (m *EmailMailer) DrainNotifyOnce(ctx context.Context, limit int) error {
	if m.smtpAddr == "" {
		return nil
	}
	rows, err := m.pool.Query(ctx, `UPDATE outbox SET status='sending'
		WHERE event_id IN (
			SELECT event_id FROM outbox
			WHERE status='pending' AND (
				topic IN (
					'auth.security.registration_attempted.v1',
					'auth.security.federated_collision.v1',
					'auth.security.federated_link_collision.v1',
					'auth.security.login_lock.v1')
				OR (topic='auth.backup.v1' AND event_type='backup.consumed')
			)
			ORDER BY created_at ASC LIMIT $1 FOR UPDATE SKIP LOCKED
		) RETURNING event_id::text, aggregate_id::text, topic, payload`, limit)
	if err != nil {
		return err
	}
	type item struct{ id, agg, topic, payload string }
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.agg, &it.topic, &it.payload); err != nil {
			rows.Close()
			return err
		}
		items = append(items, it)
	}
	rows.Close()
	for _, it := range items {
		var sendErr error
		switch it.topic {
		case "auth.security.registration_attempted.v1":
			sendErr = m.sendNotify(ctx, it.agg)
		case "auth.security.federated_collision.v1":
			sendErr = m.sendFederatedCollision(ctx, it.payload)
		case "auth.security.login_lock.v1":
			sendErr = m.sendLoginLock(ctx, it.payload)
		case "auth.backup.v1":
			sendErr = m.sendBackupConsumed(ctx, it.payload)
		default: // auth.security.federated_link_collision.v1
			sendErr = m.sendLinkCollision(ctx, it.payload)
		}
		if sendErr != nil {
			_, _ = m.pool.Exec(ctx, `UPDATE outbox SET status='pending', attempts=attempts+1 WHERE event_id=$1::uuid`, it.id)
			continue
		}
		_, _ = m.pool.Exec(ctx, `UPDATE outbox SET status='sent', sent_at=now() WHERE event_id=$1::uuid`, it.id)
	}
	return nil
}

func (m *EmailMailer) sendNotify(ctx context.Context, aggregateID string) error {
	var to string
	if err := m.pool.QueryRow(ctx, `SELECT email_normalized FROM users WHERE id=$1::uuid`, aggregateID).Scan(&to); err != nil {
		return err
	}
	// Fecha UTC + links login/forgot (SIN token ni secreto, spec §4.2/SEC-05).
	date := time.Now().UTC().Format("2006-01-02 15:04 UTC")
	base := m.frontURL
	if base == "" {
		base = "http://localhost:3000"
	}
	var b strings.Builder
	b.WriteString("Hola,\n\nAlguien intento registrar una cuenta con tu direccion de correo el " + date + ".\n")
	b.WriteString("Si fuiste tu, ignora este mensaje.\n\n")
	b.WriteString("Iniciar sesion: " + base + "/login\n")
	b.WriteString("Cambiar contrasena: " + base + "/forgot-password\n\n")
	b.WriteString("Nota anti-phishing: nunca te pediremos tu contrasena por correo.\n")
	return m.send(to, "Intentaron registrar tu direccion", b.String())
}

// sendFederatedCollision avisa al dueño (REG-04, requester anónimo).
// sendBackupConsumed avisa uso de respaldo con restantes (CU-AUTH-03, siempre).
func (m *EmailMailer) sendBackupConsumed(ctx context.Context, payloadJSON string) error {
	var p struct {
		UserID    string `json:"user_id"`
		Remaining int    `json:"remaining"`
	}
	if err := json.Unmarshal([]byte(payloadJSON), &p); err != nil || p.UserID == "" {
		return errors.New("bad backup payload")
	}
	var to string
	if err := m.pool.QueryRow(ctx, `SELECT email_normalized FROM users WHERE id=$1::uuid`, p.UserID).Scan(&to); err != nil {
		return err
	}
	extra := ""
	if p.Remaining <= 2 {
		extra = "Te quedan pocos códigos: genera nuevos desde tu cuenta.\n"
	}
	if p.Remaining == 0 {
		extra = "Ya no te quedan códigos: genera nuevos o usa tu app TOTP.\n"
	}
	return m.send(to, "Usaste un código de respaldo",
		"Hola,\n\nUsaste un código de respaldo (quedan "+itoaMail(p.Remaining)+").\n"+extra+
			"\nRegenerar códigos: "+m.base()+"/settings/security\n"+
			"Si no fuiste tú, asegura tu cuenta.\n")
}

func itoaMail(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func (m *EmailMailer) sendFederatedCollision(ctx context.Context, payloadJSON string) error {
	var p struct {
		ExistingUserID string `json:"existing_user_id"`
	}
	if err := json.Unmarshal([]byte(payloadJSON), &p); err != nil || p.ExistingUserID == "" {
		return errors.New("bad collision payload")
	}
	var to string
	if err := m.pool.QueryRow(ctx, `SELECT email_normalized FROM users WHERE id=$1::uuid`, p.ExistingUserID).Scan(&to); err != nil {
		return err
	}
	return m.send(to, "Intento de acceso con Google",
		"Hola,\n\nAlguien intento crear una cuenta con Google usando tu direccion de correo.\n"+
			"Si fuiste tu e iniciaste sesion para vincularla, ignora este mensaje.\n\n"+
			"Iniciar sesion: "+m.base()+"/login\n")
}

// sendLinkCollision avisa a AMBAS puntas sin PII cruzada (CU-REG-06 §4.2):
// cada dueño solo ve su propio email enmascarado.
func (m *EmailMailer) sendLinkCollision(ctx context.Context, payloadJSON string) error {
	var p struct {
		RequesterUserID string `json:"requester_user_id"`
		OwnerUserID     string `json:"owner_user_id"`
	}
	if err := json.Unmarshal([]byte(payloadJSON), &p); err != nil {
		return err
	}
	emailOf := func(id string) (string, error) {
		var to string
		if id == "" {
			return "", errors.New("empty user")
		}
		if err := m.pool.QueryRow(ctx, `SELECT email_normalized FROM users WHERE id=$1::uuid`, id).Scan(&to); err != nil {
			return "", err
		}
		return to, nil
	}
	reqEmail, err := emailOf(p.RequesterUserID)
	if err != nil {
		return err
	}
	ownEmail, err := emailOf(p.OwnerUserID)
	if err != nil {
		return err
	}
	if err := m.send(reqEmail, "Vinculación no realizada",
		"Hola,\n\nLa cuenta Google que intentaste vincular ("+maskLocal(reqEmail)+") ya está vinculada a otra cuenta.\n"+
			"Si crees que es un error, cambia tu contraseña.\n"); err != nil {
		return err
	}
	return m.send(ownEmail, "Intento de vinculación",
		"Hola,\n\nAlguien intento vincular tu cuenta Google ("+maskLocal(ownEmail)+") a otra cuenta.\n"+
			"Si no fuiste tú, cambia tu contraseña.\n")
}

// base URL del front para links (login/forgot).
func (m *EmailMailer) base() string {
	if m.frontURL == "" {
		return "http://localhost:3000"
	}
	return m.frontURL
}

// maskLocal enmascara para el asunto propio (u***@dominio).
func maskLocal(email string) string {
	at := strings.Index(email, "@")
	if at <= 0 {
		return "***"
	}
	return email[:1] + "***" + email[at:]
}

// sendLoginLock avisa bloqueo temporal al dueño (throttle 1/h ya aplicado).
func (m *EmailMailer) sendLoginLock(ctx context.Context, payloadJSON string) error {
	var p struct {
		UserID string `json:"user_id"`
		Email  string `json:"email"`
	}
	if err := json.Unmarshal([]byte(payloadJSON), &p); err != nil {
		return err
	}
	to := p.Email
	if to == "" && p.UserID != "" {
		if err := m.pool.QueryRow(ctx, `SELECT email_normalized FROM users WHERE id=$1::uuid`, p.UserID).Scan(&to); err != nil {
			return err
		}
	}
	if to == "" {
		return errors.New("lock email without owner")
	}
	return m.send(to, "Tu cuenta se bloqueó temporalmente",
		"Hola,\n\nDetectamos varios intentos fallidos y bloqueamos tu cuenta por seguridad.\n"+
			"Si fuiste tú, espera unos minutos e intenta de nuevo.\n\n"+
			"Iniciar sesion: "+m.base()+"/login\n"+
			"Cambiar contrasena: "+m.base()+"/forgot-password\n")
}
