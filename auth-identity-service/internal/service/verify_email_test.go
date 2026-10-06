package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/user"

	"github.com/google/uuid"
)

type mockVerifyStore struct {
	records   map[string]*auth.VerificationRecord
	byOTP     map[string]*auth.VerificationRecord
	activated map[string]string // hash -> userID
	consumeErr error
	quotaAllow bool
}

func newMockVerifyStore() *mockVerifyStore {
	return &mockVerifyStore{
		records: map[string]*auth.VerificationRecord{},
		byOTP: map[string]*auth.VerificationRecord{},
		activated: map[string]string{},
		quotaAllow: true,
	}
}

func (m *mockVerifyStore) FindAlive(_ context.Context, hash string) (*auth.VerificationRecord, error) {
	if r, ok := m.records[hash]; ok {
		if r.IsAlive(time.Now().UTC()) {
			return r, nil
		}
		return nil, auth.ErrInvalidOrExpired
	}
	if r, ok := m.byOTP[hash]; ok {
		if r.IsAlive(time.Now().UTC()) {
			return r, nil
		}
		return nil, auth.ErrInvalidOrExpired
	}
	return nil, auth.ErrInvalidOrExpired
}

func (m *mockVerifyStore) ConsumeAtomically(_ context.Context, userID, hash, method string) (*auth.ConsumedUser, error) {
	if m.consumeErr != nil {
		return nil, m.consumeErr
	}
	r, ok := m.records[hash]
	if !ok {
		r, ok = m.byOTP[hash]
	}
	if !ok || r.Consumed {
		return nil, auth.ErrInvalidOrExpired
	}
	r.Consumed = true
	m.activated[hash] = userID
	if r.OTPHash != "" {
		m.activated[r.OTPHash] = userID
	}
	if r.TokenHash != "" {
		m.activated[r.TokenHash] = userID
	}
	return &auth.ConsumedUser{UserID: userID, EmailHash: "abc", EmailDomain: "example.com", Method: method}, nil
}

func (m *mockVerifyStore) Register(_ context.Context, rec *auth.VerificationRecord) error {
	// Supersede anterior del usuario.
	for _, r := range m.records {
		if r.UserID == rec.UserID && !r.Consumed {
			r.Superseded = true
		}
	}
	m.records[rec.TokenHash] = rec
	if rec.OTPHash != "" {
		m.byOTP[rec.OTPHash] = rec
	}
	return nil
}

func (m *mockVerifyStore) IncrementAttempts(_ context.Context, hash string) (int, bool, error) {
	for _, r := range m.records {
		if r.TokenHash == hash || r.OTPHash == hash {
			r.Attempts++
			if r.Attempts >= auth.VerifyMaxAttempts {
				r.Consumed = true
				return 0, true, nil
			}
			return auth.VerifyMaxAttempts - r.Attempts, false, nil
		}
	}
	return 0, false, auth.ErrInvalidOrExpired
}

func (m *mockVerifyStore) ResendQuotaCheck(_ context.Context, _ string) (bool, time.Duration, error) {
	if !m.quotaAllow {
		return false, 60 * time.Second, nil
	}
	return true, 0, nil
}

func (m *mockVerifyStore) WasActivatedBy(_ context.Context, hash string) (string, bool, error) {
	uid, ok := m.activated[hash]
	return uid, ok, nil
}

type mockPairIssuer struct{}

func (mockPairIssuer) GeneratePair() (string, string, string, string, error) {
	return "plain-token-32bytes-test-123456", "tokhash", "87654321", "otphash", nil
}

func verifySvc(store *mockVerifyStore) (*VerifyEmailService, *mockVerifyMetrics) {
	metrics := &mockVerifyMetrics{counts: map[string]int{}}
	idem := newMockIdem()
	s := NewVerifyEmailService(store, newMockRepo(), idem, mockAudit{}, metrics, NoopTracer{})
	s.Sleep = func(time.Duration) {}
	return s, metrics
}

type mockVerifyMetrics struct {
	counts   map[string]int
	burned   int
	fallback int
	resends  map[string]int
}

func (m *mockVerifyMetrics) IncVerification(result, method string) {
	if m.counts == nil {
		m.counts = map[string]int{}
	}
	m.counts[result+"/"+method]++
}
func (m *mockVerifyMetrics) ObserveVerificationDuration(float64) {}
func (m *mockVerifyMetrics) IncResend(o string) {
	if m.resends == nil {
		m.resends = map[string]int{}
	}
	m.resends[o]++
}
func (m *mockVerifyMetrics) IncAttemptsBurned()      { m.burned++ }
func (m *mockVerifyMetrics) IncRedisFallback(string) { m.fallback++ }

func TestVerifyLinkOK(t *testing.T) {
	store := newMockVerifyStore()
	s, _ := verifySvc(store)
	plain := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 32B 'A'
	h, _ := auth.ParseTokenInput(plain)
	store.records[h] = &auth.VerificationRecord{
		UserID: "u2", TokenHash: h, OTPHash: "otp-x",
		ExpiresAt: time.Now().UTC().Add(time.Minute),
	}
	out, err := s.Execute(context.Background(), VerifyEmailInput{Token: plain, RequestID: uuid.NewString()})
	if err != nil || out.Status != "active" || out.Method != "link" {
		t.Fatalf("err=%v out=%+v", err, out)
	}
}

func TestVerifyOTPOKQuemaLink(t *testing.T) {
	store := newMockVerifyStore()
	s, _ := verifySvc(store)
	// OTP correcto activa y quema el link del mismo registro.
	if _, err := auth.ParseOTPInput("87654321"); err != nil {
		t.Fatal(err)
	}
	oh, _ := auth.ParseOTPInput("87654321")
	rec := &auth.VerificationRecord{
		UserID: "u3", TokenHash: "linkhash-otp-test", OTPHash: oh,
		ExpiresAt: time.Now().UTC().Add(time.Minute),
	}
	store.records["linkhash-otp-test"] = rec
	store.byOTP[oh] = rec
	out, err := s.Execute(context.Background(), VerifyEmailInput{Code: "87654321", RequestID: uuid.NewString()})
	if err != nil || out.Status != "active" || out.Method != "otp" {
		t.Fatalf("err=%v out=%+v", err, out)
	}
	if !rec.Consumed {
		t.Fatal("el registro debe quedar consumido (link quemado)")
	}
}

func TestVerifyExpiredConsumedMissIndistinguibles(t *testing.T) {
	store := newMockVerifyStore()
	s, _ := verifySvc(store)
	// 3 casos: aleatorio, expirado, consumido → mismo error.
	expired := &auth.VerificationRecord{UserID: "u", TokenHash: "exp", ExpiresAt: time.Now().UTC().Add(-time.Hour)}
	consumed := &auth.VerificationRecord{UserID: "u", TokenHash: "con", ExpiresAt: time.Now().UTC().Add(time.Minute), Consumed: true}
	store.records["exp"] = expired
	store.records["con"] = consumed
	for _, h := range []string{"never-existed-hash", "exp", "con"} {
		_, err := s.Store.FindAlive(context.Background(), h)
		if !errors.Is(err, auth.ErrInvalidOrExpired) {
			t.Fatalf("hash %s debe ser ErrInvalidOrExpired, got %v", h, err)
		}
	}
}

func TestVerifyRaceZeroFilas(t *testing.T) {
	store := newMockVerifyStore()
	plain := "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
	h, _ := auth.ParseTokenInput(plain)
	store.records[h] = &auth.VerificationRecord{UserID: "u", TokenHash: h, ExpiresAt: time.Now().UTC().Add(time.Minute)}
	store.consumeErr = auth.ErrInvalidOrExpired // simula carrera (UPDATE 0 filas)
	s, _ := verifySvc(store)
	_, err := s.Execute(context.Background(), VerifyEmailInput{Token: plain, RequestID: uuid.NewString()})
	if !errors.Is(err, auth.ErrInvalidOrExpired) {
		t.Fatalf("carrera debe ser ErrInvalidOrExpired, got %v", err)
	}
}

func TestVerifyIdempotentReplay(t *testing.T) {
	store := newMockVerifyStore()
	s, _ := verifySvc(store)
	plain := "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	h, _ := auth.ParseTokenInput(plain)
	store.records[h] = &auth.VerificationRecord{UserID: "u9", TokenHash: h, ExpiresAt: time.Now().UTC().Add(time.Minute)}
	reqID := uuid.NewString()
	in := VerifyEmailInput{Token: plain, RequestID: reqID}
	out1, err := s.Execute(context.Background(), in)
	if err != nil || out1.Status != "active" {
		t.Fatalf("1st: %v %+v", err, out1)
	}
	// Replay mismo RequestID → misma respuesta sin re-ejecutar (ya consumido).
	out2, err := s.Execute(context.Background(), in)
	if err != nil || out2.Status != "active" {
		t.Fatalf("replay: %v %+v", err, out2)
	}
	// Replay del link activador con OTRO RequestID → already_verified.
	out3, err := s.Execute(context.Background(), VerifyEmailInput{Token: plain, RequestID: uuid.NewString()})
	if err != nil || out3.Status != "already_verified" {
		t.Fatalf("activador: %v %+v", err, out3)
	}
}

func TestVerifyValidation(t *testing.T) {
	store := newMockVerifyStore()
	s, _ := verifySvc(store)
	// Ambos ausentes / ambos presentes.
	if _, err := s.Execute(context.Background(), VerifyEmailInput{RequestID: uuid.NewString()}); err == nil {
		t.Fatal("esperaba validation")
	}
	if _, err := s.Execute(context.Background(), VerifyEmailInput{Token: "x", Code: "12345678", RequestID: uuid.NewString()}); err == nil {
		t.Fatal("esperaba validation ambos")
	}
	if _, err := s.Execute(context.Background(), VerifyEmailInput{Code: "123", RequestID: uuid.NewString()}); err == nil {
		t.Fatal("esperaba validation OTP")
	}
	_ = user.StatusActive
}
