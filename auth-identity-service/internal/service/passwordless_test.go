package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"auth-identity-service/internal/domain/auth"

	"github.com/google/uuid"
)

// --- Fakes CU-AUTH-05 ---

type plessEligible struct {
	uid        string
	mfa        bool
	eligible   bool
}

type fakePlessStore struct {
	byEmail   map[string]plessEligible
	quotaAllow bool
	quotaErr   error
	eligibleErr error
	records   map[string]*auth.PasswordlessRecord // hash → rec
	issued    int
	consumeCalls int
	lastRisk  string
	lastMethod string
	findErr   error
	consumeErr error
	incrBurned bool
	incrCalls  int
}

func newFakePlessStore() *fakePlessStore {
	return &fakePlessStore{
		byEmail: map[string]plessEligible{}, quotaAllow: true,
		records: map[string]*auth.PasswordlessRecord{},
	}
}

func (f *fakePlessStore) Eligible(_ context.Context, email string) (string, bool, bool, error) {
	if f.eligibleErr != nil {
		return "", false, false, f.eligibleErr
	}
	if e, ok := f.byEmail[email]; ok {
		return e.uid, e.mfa, e.eligible, nil
	}
	return "", false, false, nil
}
func (f *fakePlessStore) QuotaCheck(_ context.Context, _ string) (bool, time.Duration, error) {
	if f.quotaErr != nil {
		return false, 0, f.quotaErr
	}
	return f.quotaAllow, 0, nil
}
func (f *fakePlessStore) Issue(_ context.Context, rec *auth.PasswordlessRecord) error {
	f.issued++
	f.records[rec.TokenHash] = rec
	f.records[rec.OTPHash] = rec
	return nil
}
func (f *fakePlessStore) FindAlive(_ context.Context, hash string) (*auth.PasswordlessRecord, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	if r, ok := f.records[hash]; ok {
		if !r.Alive(time.Now().UTC()) {
			return nil, auth.ErrPlessInvalid
		}
		return r, nil
	}
	return nil, auth.ErrPlessInvalid
}
func (f *fakePlessStore) ConsumeTx(_ context.Context, userID, hash, method, risk, _, _ string) (*auth.PlessConsumeResult, error) {
	f.consumeCalls++
	f.lastRisk = risk
	f.lastMethod = method
	if f.consumeErr != nil {
		return nil, f.consumeErr
	}
	r, ok := f.records[hash]
	if !ok || r.Consumed {
		return nil, auth.ErrPlessInvalid
	}
	r.Consumed = true
	mfa := false
	for _, e := range f.byEmail {
		if e.uid == userID {
			mfa = e.mfa
		}
	}
	return &auth.PlessConsumeResult{UserID: userID, MFAEnabled: mfa}, nil
}
func (f *fakePlessStore) IncrementAttempts(_ context.Context, _ string) (bool, error) {
	f.incrCalls++
	return f.incrBurned, nil
}

type fakePlessMetrics struct {
	counts   map[string]int
	mismatch map[string]int
	fallback int
	durs     map[string]int
}

func newFakePlessMetrics() *fakePlessMetrics {
	return &fakePlessMetrics{counts: map[string]int{}, mismatch: map[string]int{}, durs: map[string]int{}}
}
func (m *fakePlessMetrics) IncPless(op, r string)            { m.counts[op+"/"+r]++ }
func (m *fakePlessMetrics) ObservePlessDuration(op string, _ float64) { m.durs[op]++ }
func (m *fakePlessMetrics) IncMismatch(risk string)          { m.mismatch[risk]++ }
func (m *fakePlessMetrics) IncPlessFallback(string)          { m.fallback++ }

type plessSessFake struct {
	n       int
	lastReq auth.SessionRequest
}

func (f *plessSessFake) Issue(_ context.Context, req auth.SessionRequest) (auth.IssuedPair, error) {
	f.n++
	f.lastReq = req
	return auth.IssuedPair{
		AccessJWT: "pless-at", RefreshPlain: "pless-rt-43ch-test-vector-00000000000",
		SID: "pless-sid", JTI: "jti", Family: "fam", KID: "2026-10-a",
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}, nil
}

// token43 fixture válido (32B cero → 43 'A'; 32B unos → 43 'B').
var (
	plessTokenFixture = strings.Repeat("A", 43)
	plessTokenOther   = strings.Repeat("B", 43)
)

func plessHashToken(t *testing.T) string {
	t.Helper()
	h, err := auth.ParsePlessToken(plessTokenFixture)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func plessHashOTP(t *testing.T) string {
	t.Helper()
	h, err := auth.ParsePlessOTP("87654321")
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func plessStartSvc(store *fakePlessStore) (*PasswordlessStartService, *fakePlessMetrics, *[]time.Duration) {
	m := newFakePlessMetrics()
	s := NewPasswordlessStartService(store, mockPairIssuer{}, newMockIdem(), mockAudit{}, m, NoopTracer{})
	var sleeps []time.Duration
	s.Sleep = func(d time.Duration) { sleeps = append(sleeps, d) }
	return s, m, &sleeps
}

func TestPlessStart_ElegibleSent(t *testing.T) {
	store := newFakePlessStore()
	uid := uuid.NewString()
	store.byEmail["u@example.com"] = plessEligible{uid: uid, eligible: true}
	s, m, _ := plessStartSvc(store)
	out, err := s.Execute(context.Background(), PlessStartInput{
		EmailRaw: "U@Example.com ", RequestID: uuid.NewString(), IP: "1.2.3.4", UserAgent: "Mozilla/5.0",
	})
	if err != nil || out.Status != "if_exists_sent" {
		t.Fatalf("err=%v out=%+v", err, out)
	}
	if store.issued != 1 {
		t.Fatalf("debía emitir 1, got %d", store.issued)
	}
	if m.counts["start/sent"] != 1 {
		t.Fatalf("métrica sent: %v", m.counts)
	}
}

func TestPlessStart_OpacoNoElegible(t *testing.T) {
	store := newFakePlessStore()
	uid := uuid.NewString()
	store.byEmail["pending@example.com"] = plessEligible{uid: uid, eligible: false}
	store.byEmail["locked@example.com"] = plessEligible{uid: uuid.NewString(), eligible: false}
	s, m, sleeps := plessStartSvc(store)
	bodies := map[string]PlessStartOutput{}
	for name, email := range map[string]string{
		"inexistente": "nadie@example.com",
		"pending":     "pending@example.com",
		"locked":      "locked@example.com",
	} {
		out, err := s.Execute(context.Background(), PlessStartInput{
			EmailRaw: email, RequestID: uuid.NewString(), IP: "1.2.3.4", UserAgent: "UA",
		})
		if err != nil || out.Status != "if_exists_sent" {
			t.Fatalf("%s: err=%v out=%+v", name, err, out)
		}
		bodies[name] = *out
	}
	if bodies["inexistente"] != bodies["pending"] || bodies["pending"] != bodies["locked"] {
		t.Fatal("respuestas distinguibles")
	}
	if store.issued != 0 {
		t.Fatal("no debe emitir sin elegibilidad")
	}
	// Jitter paridad: ambas ramas duermen 60-100ms.
	for _, d := range *sleeps {
		if d < 60*time.Millisecond || d > 100*time.Millisecond {
			t.Fatalf("jitter 60-100ms, got %v", d)
		}
	}
	_ = m
}

func TestPlessStart_ValidacionYQuota(t *testing.T) {
	store := newFakePlessStore()
	s, _, _ := plessStartSvc(store)
	if _, err := s.Execute(context.Background(), PlessStartInput{EmailRaw: "no-es-email", RequestID: uuid.NewString()}); err == nil {
		t.Fatal("malformado → 400")
	}
	uid := uuid.NewString()
	store.byEmail["u@example.com"] = plessEligible{uid: uid, eligible: true}
	store.quotaAllow = false
	out, err := s.Execute(context.Background(), PlessStartInput{EmailRaw: "u@example.com", RequestID: uuid.NewString()})
	if err != nil || out.Status != "if_exists_sent" {
		t.Fatalf("throttled 202: %v %+v", err, out)
	}
	if store.issued != 0 {
		t.Fatal("throttled no emite")
	}
}

func TestPlessStart_ReplayIdempotente(t *testing.T) {
	store := newFakePlessStore()
	uid := uuid.NewString()
	store.byEmail["u@example.com"] = plessEligible{uid: uid, eligible: true}
	s, _, _ := plessStartSvc(store)
	reqID := uuid.NewString()
	in := PlessStartInput{EmailRaw: "u@example.com", RequestID: reqID}
	if _, err := s.Execute(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Execute(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if store.issued != 1 {
		t.Fatalf("replay no re-emite, got %d", store.issued)
	}
}

func TestPlessStart_InfraError(t *testing.T) {
	store := newFakePlessStore()
	store.eligibleErr = errors.New("pg down")
	s, _, _ := plessStartSvc(store)
	if _, err := s.Execute(context.Background(), PlessStartInput{EmailRaw: "u@example.com", RequestID: uuid.NewString()}); !errors.Is(err, auth.ErrInfra) {
		t.Fatalf("PG down → 500, got %v", err)
	}
}

func plessVerifySvc(store *fakePlessStore) (*PasswordlessVerifyService, *plessSessFake, *fakePlessMetrics, *fakeChal, *[]time.Duration) {
	m := newFakePlessMetrics()
	sess := &plessSessFake{}
	chal := newFakeChal()
	s := NewPasswordlessVerifyService(store, sess, &loginMFA{}, chal, newMockIdem(), mockAudit{}, m, NoopTracer{})
	var sleeps []time.Duration
	s.Sleep = func(d time.Duration) { sleeps = append(sleeps, d) }
	return s, sess, m, chal, &sleeps
}

func seedPlessRec(t *testing.T, store *fakePlessStore, uid, ip, ua string) {
	t.Helper()
	rec := &auth.PasswordlessRecord{
		UserID: uid, TokenHash: plessHashToken(t), OTPHash: plessHashOTP(t),
		ExpiresAt: time.Now().UTC().Add(auth.PlessTTL),
		Ctx:       auth.NewPlessContext(ip, ua),
	}
	store.records[rec.TokenHash] = rec
	store.records[rec.OTPHash] = rec
}

func TestPlessVerify_LinkDirectoSinMFA(t *testing.T) {
	store := newFakePlessStore()
	uid := uuid.NewString()
	store.byEmail["u@example.com"] = plessEligible{uid: uid, eligible: true}
	seedPlessRec(t, store, uid, "1.2.3.4", "Mozilla/5.0 Chrome/120")
	s, sess, m, _, _ := plessVerifySvc(store)
	out, err := s.Execute(context.Background(), PlessVerifyInput{
		Token: plessTokenFixture, RequestID: uuid.NewString(), IP: "1.2.3.4", UserAgent: "Mozilla/5.0 Chrome/120",
	})
	if err != nil || out.Status != "active" || out.Session == nil {
		t.Fatalf("err=%v out=%+v", err, out)
	}
	if sess.n != 1 {
		t.Fatal("debía emitir sesión")
	}
	if sess.lastReq.Method != auth.MethodPasswordlessEmail {
		t.Fatalf("method: %q", sess.lastReq.Method)
	}
	if len(sess.lastReq.AMR) != 1 || sess.lastReq.AMR[0] != auth.AMROTPEmail {
		t.Fatalf("amr otp-email: %v", sess.lastReq.AMR)
	}
	if out.Risk != "low" {
		t.Fatalf("mismo contexto low, got %q", out.Risk)
	}
	if m.counts["verify/success"] != 1 {
		t.Fatalf("métrica: %v", m.counts)
	}
	// Reuso → 400 (quemado).
	if _, err := s.Execute(context.Background(), PlessVerifyInput{Token: plessTokenFixture, RequestID: uuid.NewString()}); !errors.Is(err, auth.ErrPlessInvalid) {
		t.Fatalf("reuso 400, got %v", err)
	}
}

func TestPlessVerify_MFABranch(t *testing.T) {
	store := newFakePlessStore()
	uid := uuid.NewString()
	store.byEmail["u@example.com"] = plessEligible{uid: uid, mfa: true, eligible: true}
	seedPlessRec(t, store, uid, "1.2.3.4", "UA")
	s, _, m, chal, _ := plessVerifySvc(store)
	out, err := s.Execute(context.Background(), PlessVerifyInput{
		Code: "87654321", RequestID: uuid.NewString(), IP: "1.2.3.4", UserAgent: "UA",
	})
	if err != nil || out.Status != "mfa_required" || out.Challenge == nil {
		t.Fatalf("err=%v out=%+v", err, out)
	}
	if out.Session != nil {
		t.Fatal("MFA sin sesión")
	}
	if len(chal.live) != 1 {
		t.Fatal("challenge registrado single-use")
	}
	if m.counts["verify/mfa_required"] != 1 {
		t.Fatalf("métrica: %v", m.counts)
	}
}

func TestPlessVerify_400Identicos(t *testing.T) {
	newStore := func() *fakePlessStore {
		st := newFakePlessStore()
		uid := uuid.NewString()
		st.byEmail["u@example.com"] = plessEligible{uid: uid, eligible: true}
		// Expirado.
		st.records["exp"] = &auth.PasswordlessRecord{UserID: uid, TokenHash: "exp",
			ExpiresAt: time.Now().UTC().Add(-time.Minute)}
		// Consumido.
		st.records["con"] = &auth.PasswordlessRecord{UserID: uid, TokenHash: "con", OTPHash: "con",
			ExpiresAt: time.Now().UTC().Add(time.Hour), Consumed: true}
		return st
	}
	errs := map[string]error{}
	for name, in := range map[string]PlessVerifyInput{
		"expirado":  {Token: plessTokenFixture, RequestID: uuid.NewString()},
		"aleatorio": {Token: plessTokenOther, RequestID: uuid.NewString()},
	} {
		_ = name
		st := newStore()
		if name == "expirado" {
			// Registra el hash del fixture como expirado.
			h := plessHashToken(t)
			st.records[h] = &auth.PasswordlessRecord{UserID: "u", TokenHash: h,
				ExpiresAt: time.Now().UTC().Add(-time.Minute)}
		}
		s, _, _, _, sleeps := plessVerifySvc(st)
		_, err := s.Execute(context.Background(), in)
		if !errors.Is(err, auth.ErrPlessInvalid) {
			t.Fatalf("%s: got %v", name, err)
		}
		errs[name] = err
		for _, d := range *sleeps {
			if d < 40*time.Millisecond || d > 80*time.Millisecond {
				t.Fatalf("delay 40-80ms, got %v", d)
			}
		}
	}
	if errs["expirado"].Error() != errs["aleatorio"].Error() {
		t.Fatal("400 indistinguibles")
	}
}

func TestPlessVerify_ConsumidoYQuemado(t *testing.T) {
	store := newFakePlessStore()
	uid := uuid.NewString()
	store.byEmail["u@example.com"] = plessEligible{uid: uid, eligible: true}
	h := plessHashToken(t)
	store.records[h] = &auth.PasswordlessRecord{UserID: uid, TokenHash: h, OTPHash: plessHashOTP(t),
		ExpiresAt: time.Now().UTC().Add(time.Hour), Consumed: true}
	s, _, _, _, _ := plessVerifySvc(store)
	if _, err := s.Execute(context.Background(), PlessVerifyInput{Token: plessTokenFixture, RequestID: uuid.NewString()}); !errors.Is(err, auth.ErrPlessInvalid) {
		t.Fatalf("consumido 400, got %v", err)
	}
	// Quema en 3º fallo: mismatch fuerza IncrementAttempts.
	store2 := newFakePlessStore()
	store2.records["x"] = &auth.PasswordlessRecord{UserID: "u", TokenHash: "other",
		ExpiresAt: time.Now().UTC().Add(time.Hour)}
	store2.incrBurned = true
	s2, _, m2, _, _ := plessVerifySvc(store2)
	if _, err := s2.Execute(context.Background(), PlessVerifyInput{Token: plessTokenFixture, RequestID: uuid.NewString()}); !errors.Is(err, auth.ErrPlessInvalid) {
		t.Fatalf("quemado 400, got %v", err)
	}
	_ = m2
}

func TestPlessVerify_ReplayIdempotente(t *testing.T) {
	store := newFakePlessStore()
	uid := uuid.NewString()
	store.byEmail["u@example.com"] = plessEligible{uid: uid, eligible: true}
	seedPlessRec(t, store, uid, "1.1.1.1", "UA")
	s, sess, _, _, _ := plessVerifySvc(store)
	reqID := uuid.NewString()
	in := PlessVerifyInput{Token: plessTokenFixture, RequestID: reqID, IP: "1.1.1.1", UserAgent: "UA"}
	out, err := s.Execute(context.Background(), in)
	if err != nil || out.Status != "active" {
		t.Fatalf("%v %+v", err, out)
	}
	out2, err := s.Execute(context.Background(), in)
	if err != nil || out2.Status != "active" {
		t.Fatalf("replay: %v %+v", err, out2)
	}
	if store.consumeCalls != 1 || sess.n != 1 {
		t.Fatalf("sin re-consumir: consume=%d issue=%d", store.consumeCalls, sess.n)
	}
}

func TestPlessVerify_HighRiskMismatch(t *testing.T) {
	store := newFakePlessStore()
	uid := uuid.NewString()
	store.byEmail["u@example.com"] = plessEligible{uid: uid, eligible: true}
	seedPlessRec(t, store, uid, "192.168.1.10", "Mozilla/5.0 Chrome/120")
	s, _, m, _, _ := plessVerifySvc(store)
	out, err := s.Execute(context.Background(), PlessVerifyInput{
		Token: plessTokenFixture, RequestID: uuid.NewString(),
		IP: "10.20.30.40", UserAgent: "okhttp/4.12",
	})
	if err != nil || out.Status != "active" {
		t.Fatalf("high-risk igual 200: %v %+v", err, out)
	}
	if out.Risk != "high" || store.lastRisk != "high" {
		t.Fatalf("risk high: out=%q store=%q", out.Risk, store.lastRisk)
	}
	if m.mismatch["high"] != 1 {
		t.Fatalf("mismatch metric: %v", m.mismatch)
	}
}

func TestPlessVerify_ValidacionEInfra(t *testing.T) {
	store := newFakePlessStore()
	s, _, _, _, _ := plessVerifySvc(store)
	for name, in := range map[string]PlessVerifyInput{
		"ambos":   {Token: "x", Code: "y", RequestID: uuid.NewString()},
		"ninguno": {RequestID: uuid.NewString()},
		"token-malo": {Token: "corto", RequestID: uuid.NewString()},
		"code-malo":  {Code: "12", RequestID: uuid.NewString()},
	} {
		if _, err := s.Execute(context.Background(), in); err == nil {
			t.Fatalf("%s: debía fallar forma", name)
		}
	}
	store.findErr = errors.New("pg down")
	if _, err := s.Execute(context.Background(), PlessVerifyInput{Token: plessTokenFixture, RequestID: uuid.NewString()}); !errors.Is(err, auth.ErrInfra) {
		t.Fatalf("PG down 500, got %v", err)
	}
}
