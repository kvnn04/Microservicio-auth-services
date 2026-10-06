package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/user"

	"github.com/google/uuid"
)

// --- Fakes CU-CRED-01 ---

type resetEligible struct {
	uid      string
	eligible bool
	hint     bool
}

type fakeResetStore struct {
	byEmail      map[string]resetEligible
	users        map[string]*user.User
	quotaAllow   bool
	quotaErr     error
	eligibleErr  error
	records      map[string]*auth.PasswordResetRecord
	issued       int
	hints        int
	findErr      error
	consumeErr   error
	consumeCalls int
	lastNewHash  string
	lastRisk     string
	incrCalls    int
}

func newFakeResetStore() *fakeResetStore {
	return &fakeResetStore{
		byEmail: map[string]resetEligible{}, users: map[string]*user.User{},
		quotaAllow: true, records: map[string]*auth.PasswordResetRecord{},
	}
}

func (f *fakeResetStore) EligibleForReset(_ context.Context, email string) (string, bool, bool, error) {
	if f.eligibleErr != nil {
		return "", false, false, f.eligibleErr
	}
	if e, ok := f.byEmail[email]; ok {
		return e.uid, e.eligible, e.hint, nil
	}
	return "", false, false, nil
}
func (f *fakeResetStore) QuotaCheck(_ context.Context, _ string) (bool, time.Duration, error) {
	if f.quotaErr != nil {
		return false, 0, f.quotaErr
	}
	return f.quotaAllow, 0, nil
}
func (f *fakeResetStore) Issue(_ context.Context, rec *auth.PasswordResetRecord) error {
	f.issued++
	f.records[rec.TokenHash] = rec
	return nil
}
func (f *fakeResetStore) IssueHint(_ context.Context, uid, _ string) error {
	f.hints++
	return nil
}
func (f *fakeResetStore) FindAlive(_ context.Context, hash string) (*auth.PasswordResetRecord, *user.User, error) {
	if f.findErr != nil {
		return nil, nil, f.findErr
	}
	r, ok := f.records[hash]
	if !ok || !r.Alive(time.Now().UTC()) {
		return nil, nil, auth.ErrPwdResetInvalid
	}
	u, ok := f.users[r.UserID]
	if !ok {
		return nil, nil, auth.ErrPwdResetInvalid
	}
	return r, u, nil
}
func (f *fakeResetStore) ConsumeTx(_ context.Context, userID, hash, newHash, risk, _, _, _ string) error {
	f.consumeCalls++
	f.lastNewHash = newHash
	f.lastRisk = risk
	if f.consumeErr != nil {
		return f.consumeErr
	}
	r, ok := f.records[hash]
	if !ok || r.Consumed {
		return auth.ErrPwdResetInvalid
	}
	if u, ok := f.users[userID]; ok {
		u.PasswordHash = newHash
	}
	r.Consumed = true
	return nil
}
func (f *fakeResetStore) IncrementAttempts(_ context.Context, hash string) (bool, error) {
	f.incrCalls++
	if r, ok := f.records[hash]; ok {
		r.Attempts++
		if r.Attempts >= auth.PwdResetMaxAttempts {
			return true, nil
		}
	}
	return false, nil
}

type fakeResetMetrics struct {
	counts   map[string]int
	hibp     int
	mismatch map[string]int
	fallback int
	durs     map[string]int
}

func newFakeResetMetrics() *fakeResetMetrics {
	return &fakeResetMetrics{counts: map[string]int{}, mismatch: map[string]int{}, durs: map[string]int{}}
}
func (m *fakeResetMetrics) IncReset(op, r string)                     { m.counts[op+"/"+r]++ }
func (m *fakeResetMetrics) ObserveResetDuration(op string, _ float64) { m.durs[op]++ }
func (m *fakeResetMetrics) IncHibpFallback()                          { m.hibp++ }
func (m *fakeResetMetrics) IncMismatch(risk string)                   { m.mismatch[risk]++ }
func (m *fakeResetMetrics) IncResetFallback(string)                   { m.fallback++ }

type fakeBreach struct {
	compromised bool
	err         error
}

func (f *fakeBreach) IsCompromised(_ context.Context, _ string) (bool, error) {
	return f.compromised, f.err
}

var resetTokenFixture = strings.Repeat("A", 43) // 32B cero

func resetHash(t *testing.T) string {
	t.Helper()
	h, err := auth.ParseResetToken(resetTokenFixture)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func resetStartSvc(store *fakeResetStore) (*PasswordResetStartService, *fakeResetMetrics, *[]time.Duration) {
	m := newFakeResetMetrics()
	s := NewPasswordResetStartService(store, mockPairIssuer{}, newMockIdem(), mockAudit{}, m, NoopTracer{})
	var sleeps []time.Duration
	s.Sleep = func(d time.Duration) { sleeps = append(sleeps, d) }
	return s, m, &sleeps
}

func seedResetUser(store *fakeResetStore, email string, withPassword, active bool) string {
	uid := uuid.NewString()
	pw := ""
	if withPassword {
		pw = "$argon2id$v=19$m=65536,t=3,p=4$salt$hash"
	}
	status := user.StatusActive
	if !active {
		status = user.StatusPendingVerification
	}
	store.users[uid] = &user.User{ID: uid, EmailNormalized: email, EmailOriginal: email,
		PasswordHash: pw, Status: status}
	return uid
}

func TestPwdResetStart_ElegibleSent(t *testing.T) {
	store := newFakeResetStore()
	uid := seedResetUser(store, "u@example.com", true, true)
	store.byEmail["u@example.com"] = resetEligible{uid: uid, eligible: true}
	s, m, _ := resetStartSvc(store)
	out, err := s.Execute(context.Background(), PwdResetStartInput{
		EmailRaw: "U@Example.com ", RequestID: uuid.NewString(), IP: "1.2.3.4", UserAgent: "UA",
	})
	if err != nil || out.Status != "if_exists_sent" {
		t.Fatalf("err=%v out=%+v", err, out)
	}
	if store.issued != 1 || m.counts["start/sent"] != 1 {
		t.Fatalf("issued=%d metrics=%v", store.issued, m.counts)
	}
}

func TestPwdResetStart_OpacosYHint(t *testing.T) {
	store := newFakeResetStore()
	uidP := seedResetUser(store, "pending@example.com", true, false)
	store.byEmail["pending@example.com"] = resetEligible{uid: uidP}
	uidF := seedResetUser(store, "fed@example.com", false, true)
	store.byEmail["fed@example.com"] = resetEligible{uid: uidF, hint: true}
	s, m, _ := resetStartSvc(store)
	bodies := map[string]PwdResetStartOutput{}
	for name, email := range map[string]string{
		"inexistente": "nadie@example.com",
		"pending":     "pending@example.com",
		"federated":   "fed@example.com",
	} {
		out, err := s.Execute(context.Background(), PwdResetStartInput{
			EmailRaw: email, RequestID: uuid.NewString(),
		})
		if err != nil || out.Status != "if_exists_sent" {
			t.Fatalf("%s: %v %+v", name, err, out)
		}
		bodies[name] = *out
	}
	if bodies["inexistente"] != bodies["pending"] || bodies["pending"] != bodies["federated"] {
		t.Fatal("202 distinguibles")
	}
	if store.issued != 0 || store.hints != 1 {
		t.Fatalf("hint 1 sin link: issued=%d hints=%d", store.issued, store.hints)
	}
	if m.counts["start/federated_hint"] != 1 || m.counts["start/not_eligible"] != 2 {
		t.Fatalf("métricas: %v", m.counts)
	}
}

func TestPwdResetStart_ValidacionQuotaReplay(t *testing.T) {
	store := newFakeResetStore()
	s, _, sleeps := resetStartSvc(store)
	if _, err := s.Execute(context.Background(), PwdResetStartInput{EmailRaw: "no-es-email", RequestID: uuid.NewString()}); err == nil {
		t.Fatal("malformado 400")
	}
	uid := seedResetUser(store, "u@example.com", true, true)
	store.byEmail["u@example.com"] = resetEligible{uid: uid, eligible: true}
	store.quotaAllow = false
	out, err := s.Execute(context.Background(), PwdResetStartInput{EmailRaw: "u@example.com", RequestID: uuid.NewString()})
	if err != nil || out.Status != "if_exists_sent" || store.issued != 0 {
		t.Fatalf("throttled 202: %v %+v issued=%d", err, out, store.issued)
	}
	for _, d := range *sleeps {
		if d < 60*time.Millisecond || d > 100*time.Millisecond {
			t.Fatalf("jitter 60-100: %v", d)
		}
	}
	store.quotaAllow = true
	reqID := uuid.NewString()
	in := PwdResetStartInput{EmailRaw: "u@example.com", RequestID: reqID}
	if _, err := s.Execute(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Execute(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if store.issued != 1 {
		t.Fatalf("replay no re-emite: %d", store.issued)
	}
}

func resetConfirmSvc(store *fakeResetStore, hasher *stepHasher, breach *fakeBreach) (*PasswordResetConfirmService, *fakeResetMetrics, *[]time.Duration) {
	m := newFakeResetMetrics()
	var b auth.BreachChecker
	if breach != nil {
		b = breach
	}
	s := NewPasswordResetConfirmService(store, hasher, b, newMockIdem(), mockAudit{}, m, NoopTracer{})
	var sleeps []time.Duration
	s.Sleep = func(d time.Duration) { sleeps = append(sleeps, d) }
	return s, m, &sleeps
}

func TestPwdResetConfirm_OKSinAutoLogin(t *testing.T) {
	store := newFakeResetStore()
	uid := seedResetUser(store, "u@example.com", true, true)
	store.records[resetHash(t)] = &auth.PasswordResetRecord{
		UserID: uid, TokenHash: resetHash(t),
		ExpiresAt: time.Now().UTC().Add(auth.PwdResetTTL),
		Ctx:       auth.NewPlessContext("1.2.3.4", "Mozilla/5.0"),
	}
	s, m, _ := resetConfirmSvc(store, &stepHasher{ok: false}, nil)
	out, err := s.Execute(context.Background(), PwdResetConfirmInput{
		Token: resetTokenFixture, NewPassword: "Nu3va!Valida-2026",
		RequestID: uuid.NewString(), IP: "1.2.3.4", UserAgent: "Mozilla/5.0",
	})
	if err != nil || out.Status != "password_changed" {
		t.Fatalf("err=%v out=%+v", err, out)
	}
	// stepHasher.Hash retorna "hash" fijo: el fake lo persiste tal cual.
	if store.users[uid].PasswordHash != "hash" {
		t.Fatal("clave rotada en el usuario")
	}
	if store.lastNewHash != "hash" {
		t.Fatal("newHash pasó por la Tx")
	}
	if m.counts["confirm/success"] != 1 {
		t.Fatalf("métrica: %v", m.counts)
	}
	// Reuso del link → 400 (quemado).
	if _, err := s.Execute(context.Background(), PwdResetConfirmInput{
		Token: resetTokenFixture, NewPassword: "Nu3va!Valida-2026", RequestID: uuid.NewString(),
	}); !errors.Is(err, auth.ErrPwdResetInvalid) {
		t.Fatalf("reuso 400: %v", err)
	}
}

func TestPwdResetConfirm_400Identicos(t *testing.T) {
	mk := func() (*PasswordResetConfirmService, *fakeResetStore, *[]time.Duration) {
		store := newFakeResetStore()
		uid := seedResetUser(store, "u@example.com", true, true)
		h := resetHash(t)
		store.records[h] = &auth.PasswordResetRecord{
			UserID: uid, TokenHash: h,
			ExpiresAt: time.Now().UTC().Add(-time.Minute),
			Ctx:       auth.NewPlessContext("1.1.1.1", "UA"),
		}
		s, _, sleeps := resetConfirmSvc(store, &stepHasher{ok: false}, nil)
		return s, store, sleeps
	}
	errs := map[string]error{}
	in := map[string]PwdResetConfirmInput{
		"expirado":  {Token: resetTokenFixture, NewPassword: "Nu3va!Valida-2026", RequestID: uuid.NewString()},
		"aleatorio": {Token: strings.Repeat("B", 43), NewPassword: "Nu3va!Valida-2026", RequestID: uuid.NewString()},
	}
	for name, input := range in {
		s, _, sleeps := mk()
		// El caso aleatorio necesita store sin el registro expirado.
		if name == "aleatorio" {
			store := newFakeResetStore()
			seedResetUser(store, "u@example.com", true, true)
			s, _, sleeps = resetConfirmSvc(store, &stepHasher{ok: false}, nil)
		}
		_, err := s.Execute(context.Background(), input)
		if !errors.Is(err, auth.ErrPwdResetInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
		errs[name] = err
		for _, d := range *sleeps {
			if d < 40*time.Millisecond || d > 80*time.Millisecond {
				t.Fatalf("delay 40-80ms: %v", d)
			}
		}
	}
	if errs["expirado"].Error() != errs["aleatorio"].Error() {
		t.Fatal("400 indistinguibles")
	}
}

func TestPwdResetConfirm_PolicyYReusedSinQuemar(t *testing.T) {
	newStore := func() (*fakeResetStore, string) {
		store := newFakeResetStore()
		uid := seedResetUser(store, "u@example.com", true, true)
		store.records[resetHash(t)] = &auth.PasswordResetRecord{
			UserID: uid, TokenHash: resetHash(t),
			ExpiresAt: time.Now().UTC().Add(auth.PwdResetTTL),
			Ctx:       auth.NewPlessContext("1.1.1.1", "UA"),
		}
		return store, uid
	}
	// Débil → POLICY con detalle, token intacto.
	store, _ := newStore()
	s, _, _ := resetConfirmSvc(store, &stepHasher{ok: false}, nil)
	_, err := s.Execute(context.Background(), PwdResetConfirmInput{
		Token: resetTokenFixture, NewPassword: "corta", RequestID: uuid.NewString(),
	})
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Fields[0].Reason != "TOO_SHORT" {
		t.Fatalf("policy detalle: %v", err)
	}
	if !store.records[resetHash(t)].Alive(time.Now().UTC()) {
		t.Fatal("policy-fail no quema")
	}
	// Igual a actual → REUSED, cuenta abuso pero no quema este intento.
	store2, _ := newStore()
	s2, _, _ := resetConfirmSvc(store2, &stepHasher{ok: true}, nil)
	_, err = s2.Execute(context.Background(), PwdResetConfirmInput{
		Token: resetTokenFixture, NewPassword: "Nu3va!Valida-2026", RequestID: uuid.NewString(),
	})
	if !errors.Is(err, auth.ErrPasswordReused) {
		t.Fatalf("reused: %v", err)
	}
	if store2.incrCalls != 1 {
		t.Fatal("reused cuenta abuso")
	}
	if !store2.records[resetHash(t)].Alive(time.Now().UTC()) {
		t.Fatal("reused no quema este intento")
	}
	// 3º abuso → burn: mismo token con Attempts=2 + reused ⇒ Attempts=3 ⇒ inválido.
	store3, _ := newStore()
	store3.records[resetHash(t)].Attempts = 2
	s3, _, _ := resetConfirmSvc(store3, &stepHasher{ok: true}, nil)
	if _, err := s3.Execute(context.Background(), PwdResetConfirmInput{
		Token: resetTokenFixture, NewPassword: "Nu3va!Valida-2026", RequestID: uuid.NewString(),
	}); !errors.Is(err, auth.ErrPasswordReused) {
		t.Fatalf("3º aún reused: %v", err)
	}
	s3b, _, _ := resetConfirmSvc(store3, &stepHasher{ok: false}, nil)
	if _, err := s3b.Execute(context.Background(), PwdResetConfirmInput{
		Token: resetTokenFixture, NewPassword: "0tra!Valida-2026", RequestID: uuid.NewString(),
	}); !errors.Is(err, auth.ErrPwdResetInvalid) {
		t.Fatalf("quemado 400: %v", err)
	}
}

func TestPwdResetConfirm_ReplayYHighRisk(t *testing.T) {
	store := newFakeResetStore()
	uid := seedResetUser(store, "u@example.com", true, true)
	store.records[resetHash(t)] = &auth.PasswordResetRecord{
		UserID: uid, TokenHash: resetHash(t),
		ExpiresAt: time.Now().UTC().Add(auth.PwdResetTTL),
		Ctx:       auth.NewPlessContext("192.168.1.10", "Mozilla/5.0 Chrome/120"),
	}
	s, m, _ := resetConfirmSvc(store, &stepHasher{ok: false}, nil)
	reqID := uuid.NewString()
	in := PwdResetConfirmInput{Token: resetTokenFixture, NewPassword: "Nu3va!Valida-2026",
		RequestID: reqID, IP: "10.20.30.40", UserAgent: "okhttp/4.12"}
	out, err := s.Execute(context.Background(), in)
	if err != nil || out.Status != "password_changed" {
		t.Fatalf("%v %+v", err, out)
	}
	if store.lastRisk != "high" || m.mismatch["high"] != 1 {
		t.Fatalf("high-risk: %q %v", store.lastRisk, m.mismatch)
	}
	out2, err := s.Execute(context.Background(), in)
	if err != nil || out2.Status != "password_changed" {
		t.Fatalf("replay: %v %+v", err, out2)
	}
	if store.consumeCalls != 1 {
		t.Fatalf("sin re-consumir: %d", store.consumeCalls)
	}
}

func TestPwdResetConfirm_ValidacionHIBPInfra(t *testing.T) {
	store := newFakeResetStore()
	s, _, _ := resetConfirmSvc(store, &stepHasher{ok: false}, nil)
	for name, in := range map[string]PwdResetConfirmInput{
		"token-malo": {Token: "corto", NewPassword: "Nu3va!Valida-2026", RequestID: uuid.NewString()},
		"sin-clave":  {Token: resetTokenFixture, RequestID: uuid.NewString()},
		"mismatch":   {Token: resetTokenFixture, NewPassword: "Nu3va!Valida-2026", Confirm: "0tra!Valida-2026", HasConfirm: true, RequestID: uuid.NewString()},
	} {
		if _, err := s.Execute(context.Background(), in); err == nil {
			t.Fatalf("%s: debía fallar forma", name)
		}
	}
	// HIBP comprometida → POLICY.
	store2 := newFakeResetStore()
	uid := seedResetUser(store2, "u@example.com", true, true)
	store2.records[resetHash(t)] = &auth.PasswordResetRecord{
		UserID: uid, TokenHash: resetHash(t),
		ExpiresAt: time.Now().UTC().Add(auth.PwdResetTTL),
	}
	s2, _, _ := resetConfirmSvc(store2, &stepHasher{ok: false}, &fakeBreach{compromised: true})
	_, err := s2.Execute(context.Background(), PwdResetConfirmInput{
		Token: resetTokenFixture, NewPassword: "Nu3va!Valida-2026", RequestID: uuid.NewString(),
	})
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("hibp: %v", err)
	}
	// HIBP caído + clave fuera de deny-list → fallback local, el flujo sigue.
	store2b := newFakeResetStore()
	uid2 := seedResetUser(store2b, "u@example.com", true, true)
	store2b.records[resetHash(t)] = &auth.PasswordResetRecord{
		UserID: uid2, TokenHash: resetHash(t),
		ExpiresAt: time.Now().UTC().Add(auth.PwdResetTTL),
	}
	s2b, m2b, _ := resetConfirmSvc(store2b, &stepHasher{ok: false}, &fakeBreach{err: errors.New("timeout")})
	out2b, err := s2b.Execute(context.Background(), PwdResetConfirmInput{
		Token: resetTokenFixture, NewPassword: "Nu3va!Valida-2026", RequestID: uuid.NewString(),
	})
	if err != nil || out2b.Status != "password_changed" {
		t.Fatalf("hibp-fallback: %v %+v", err, out2b)
	}
	if m2b.hibp != 1 {
		t.Fatal("métrica hibp_fallback")
	}
	// PG down → 500 sin cambios.
	store3 := newFakeResetStore()
	store3.findErr = errors.New("pg down")
	s3, _, _ := resetConfirmSvc(store3, &stepHasher{ok: false}, nil)
	if _, err := s3.Execute(context.Background(), PwdResetConfirmInput{
		Token: resetTokenFixture, NewPassword: "Nu3va!Valida-2026", RequestID: uuid.NewString(),
	}); !errors.Is(err, auth.ErrInfra) {
		t.Fatalf("pg down 500: %v", err)
	}
}
