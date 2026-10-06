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

// --- Fakes CU-CRED-03 ---

type emailChangeUser struct {
	id     string
	email  string
	active bool
}

type fakeEmailChangeStore struct {
	users      map[string]*emailChangeUser // by email
	byID       map[string]*emailChangeUser
	quotaAllow bool
	takenErr   error
	records    map[string]*user.EmailChangeRecord
	issued     int
	hints      int
	findErr    error
	consumeErr error
	consumeCalls int
	incrCalls  int
}

func newFakeEmailChangeStore() *fakeEmailChangeStore {
	return &fakeEmailChangeStore{
		users: map[string]*emailChangeUser{}, byID: map[string]*emailChangeUser{},
		quotaAllow: true, records: map[string]*user.EmailChangeRecord{},
	}
}

func (f *fakeEmailChangeStore) seedActive(email string) string {
	uid := uuid.NewString()
	u := &emailChangeUser{id: uid, email: email, active: true}
	f.users[email] = u
	f.byID[uid] = u
	return uid
}

func (f *fakeEmailChangeStore) QuotaCheck(_ context.Context, _ string) (bool, time.Duration, error) {
	return f.quotaAllow, 0, nil
}
func (f *fakeEmailChangeStore) Taken(_ context.Context, newNorm, requesterID string) (bool, error) {
	if f.takenErr != nil {
		return false, f.takenErr
	}
	if u, ok := f.users[newNorm]; ok && u.id != requesterID {
		return true, nil
	}
	return false, nil
}
func (f *fakeEmailChangeStore) Issue(_ context.Context, rec *user.EmailChangeRecord) error {
	f.issued++
	f.records[rec.TokenHash] = rec
	return nil
}
func (f *fakeEmailChangeStore) FindAlive(_ context.Context, hash string) (*user.EmailChangeRecord, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	r, ok := f.records[hash]
	if !ok || !r.Alive(time.Now().UTC()) {
		return nil, user.ErrEmailChangeInvalid
	}
	return r, nil
}
func (f *fakeEmailChangeStore) ConfirmTx(_ context.Context, hash string) (string, string, error) {
	f.consumeCalls++
	if f.consumeErr != nil {
		return "", "", f.consumeErr
	}
	r, ok := f.records[hash]
	if !ok || r.Consumed {
		return "", "", user.ErrEmailChangeInvalid
	}
	if u, taken := f.users[r.NewNormalized]; taken && u.id != r.RequesterID {
		r.Consumed = true // quema el token intentado
		return "", "", user.ErrEmailAlreadyInUse
	}
	r.Consumed = true
	return r.RequesterID, r.NewNormalized, nil
}
func (f *fakeEmailChangeStore) IncrementAttempts(_ context.Context, hash string) (bool, error) {
	f.incrCalls++
	if r, ok := f.records[hash]; ok {
		r.Attempts++
		if r.Attempts >= user.EmailChangeMaxAttempts {
			return true, nil
		}
	}
	return false, nil
}

type emailChangeRepo struct {
	users map[string]*user.User
}

func (r *emailChangeRepo) FindByEmailNormalized(_ context.Context, e string) (*user.User, error) {
	if u, ok := r.users[e]; ok {
		return u, nil
	}
	return nil, user.ErrNotFound
}
func (r *emailChangeRepo) FindByID(_ context.Context, id string) (*user.User, error) {
	for _, u := range r.users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, user.ErrNotFound
}
func (r *emailChangeRepo) CreateWithOutbox(_ context.Context, _ *user.User, _ []user.OutboxPayload, _ string, _ string) error {
	return nil
}
func (r *emailChangeRepo) CreateWithConsents(_ context.Context, _ *user.User, _ []user.OutboxPayload, _ string, _ user.RegistrationContext) error {
	return nil
}

type fakeEmailMetrics struct {
	counts   map[string]int
	fallback int
	durs     map[string]int
}

func newFakeEmailMetrics() *fakeEmailMetrics {
	return &fakeEmailMetrics{counts: map[string]int{}, durs: map[string]int{}}
}
func (m *fakeEmailMetrics) IncEmailChange(op, r string)                 { m.counts[op+"/"+r]++ }
func (m *fakeEmailMetrics) ObserveEmailChangeDuration(op string, _ float64) { m.durs[op]++ }
func (m *fakeEmailMetrics) IncEmailChangeFallback(string)              { m.fallback++ }

type fakeEmailStepUp struct {
	mode string
	err  error
}

func (f *fakeEmailStepUp) Check(_ context.Context, _ string, _ time.Time, _ auth.StepUpScope, _ string) (string, error) {
	return f.mode, f.err
}

func emailStartSvc(store *fakeEmailChangeStore, repo *emailChangeRepo) (*EmailChangeStartService, *fakeEmailMetrics) {
	m := newFakeEmailMetrics()
	s := NewEmailChangeStartService(repo, store, &fakeEmailStepUp{},
		mockPairIssuer{}, newMockIdem(), mockAudit{}, m, NoopTracer{})
	return s, m
}

func seedEmailUser(repo *emailChangeRepo, store *fakeEmailChangeStore, email string) string {
	uid := store.seedActive(email)
	repo.users[email] = &user.User{ID: uid, EmailNormalized: email, Status: user.StatusActive}
	return uid
}

func emailStartIn(uid, newEmail string) EmailChangeStartInput {
	return EmailChangeStartInput{
		User: AuthUser{ID: uid, AuthTime: time.Now().UTC().Add(-time.Minute)},
		NewEmailRaw: newEmail, RequestID: uuid.NewString(),
	}
}

func TestEmailChangeStart_FrescoSent(t *testing.T) {
	store := newFakeEmailChangeStore()
	repo := &emailChangeRepo{users: map[string]*user.User{}}
	uid := seedEmailUser(repo, store, "viejo@example.com")
	s, m := emailStartSvc(store, repo)
	out, err := s.Execute(context.Background(), emailStartIn(uid, "Nuevo@Example.com "))
	if err != nil || out.Status != "confirmation_sent" || out.Masked != "n***@example.com" {
		t.Fatalf("err=%v out=%+v", err, out)
	}
	if store.issued != 1 || m.counts["start/sent"] != 1 {
		t.Fatalf("issued=%d metrics=%v", store.issued, m.counts)
	}
}

func TestEmailChangeStart_Stale401TakenThrottled(t *testing.T) {
	// Stale sin token → 401 sin crear nada.
	store := newFakeEmailChangeStore()
	repo := &emailChangeRepo{users: map[string]*user.User{}}
	uid := seedEmailUser(repo, store, "viejo@example.com")
	s, _ := emailStartSvc(store, repo)
	s.StepUp = &fakeEmailStepUp{err: auth.ErrStepUpRequired}
	if _, err := s.Execute(context.Background(), emailStartIn(uid, "nuevo@example.com")); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("stale: %v", err)
	}
	if store.issued != 0 {
		t.Fatal("sin crear nada")
	}
	// Tomado → 409 + audit (0 correos al nuevo).
	other := seedEmailUser(repo, store, "ocupado@example.com")
	_ = other
	s2, m2 := emailStartSvc(store, repo)
	if _, err := s2.Execute(context.Background(), emailStartIn(uid, "ocupado@example.com")); !errors.Is(err, user.ErrEmailAlreadyInUse) {
		t.Fatalf("taken: %v", err)
	}
	if m2.counts["start/taken"] != 1 || store.issued != 0 {
		t.Fatalf("taken metric/issue: %v %d", m2.counts, store.issued)
	}
	// Throttled → 429 con retry.
	s3, _ := emailStartSvc(store, repo)
	store.quotaAllow = false
	_, err := s3.Execute(context.Background(), emailStartIn(uid, "libre@example.com"))
	var throt *ThrottledError
	if !errors.As(err, &throt) {
		t.Fatalf("throttled: %v", err)
	}
}

func TestEmailChangeStart_ValidacionYReplay(t *testing.T) {
	store := newFakeEmailChangeStore()
	repo := &emailChangeRepo{users: map[string]*user.User{}}
	uid := seedEmailUser(repo, store, "viejo@example.com")
	s, _ := emailStartSvc(store, repo)
	if _, err := s.Execute(context.Background(), emailStartIn(uid, "no-es-email")); err == nil {
		t.Fatal("malformado 400")
	}
	in := emailStartIn(uid, "nuevo@example.com")
	in.NewEmailRaw = "viejo@example.com"
	if _, err := s.Execute(context.Background(), in); err == nil {
		t.Fatal("igual-actual 400")
	}
	reqID := uuid.NewString()
	in2 := emailStartIn(uid, "nuevo2@example.com")
	in2.RequestID = reqID
	if _, err := s.Execute(context.Background(), in2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Execute(context.Background(), in2); err != nil {
		t.Fatal(err)
	}
	if store.issued != 1 {
		t.Fatalf("replay no re-emite: %d", store.issued)
	}
}

func emailConfirmSvc(store *fakeEmailChangeStore) (*EmailChangeConfirmService, *fakeEmailMetrics, *[]time.Duration) {
	m := newFakeEmailMetrics()
	s := NewEmailChangeConfirmService(store, newMockIdem(), mockAudit{}, m, NoopTracer{})
	var sleeps []time.Duration
	s.Sleep = func(d time.Duration) { sleeps = append(sleeps, d) }
	return s, m, &sleeps
}

func seedEmailRec(t *testing.T, store *fakeEmailChangeStore, uid, newEmail string) string {
	t.Helper()
	plain := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if len(plain) != 43 {
		t.Fatal("fixture")
	}
	h, err := user.ParseEmailChangeToken(plain)
	if err != nil {
		t.Fatal(err)
	}
	store.records[h] = &user.EmailChangeRecord{
		RequesterID: uid, TokenHash: h, NewNormalized: newEmail, NewOriginal: newEmail,
		ExpiresAt: time.Now().UTC().Add(user.EmailChangeTTL),
	}
	return plain
}

func TestEmailChangeConfirm_OKRevocaTodo(t *testing.T) {
	store := newFakeEmailChangeStore()
	uid := store.seedActive("viejo@example.com")
	plain := seedEmailRec(t, store, uid, "nuevo@example.com")
	s, m, _ := emailConfirmSvc(store)
	out, err := s.Execute(context.Background(), EmailChangeConfirmInput{
		Token: plain, RequestID: uuid.NewString(),
	})
	if err != nil || out.Status != "email_changed" || out.Masked != "n***@example.com" {
		t.Fatalf("err=%v out=%+v", err, out)
	}
	if m.counts["confirm/success"] != 1 || store.consumeCalls != 1 {
		t.Fatalf("métricas/consumo: %v %d", m.counts, store.consumeCalls)
	}
	// Reuso → 400.
	if _, err := s.Execute(context.Background(), EmailChangeConfirmInput{
		Token: plain, RequestID: uuid.NewString(),
	}); err == nil {
		t.Fatal("reuso 400")
	}
}

func TestEmailChangeConfirm_RaceTakenQuema(t *testing.T) {
	store := newFakeEmailChangeStore()
	uid := store.seedActive("viejo@example.com")
	other := store.seedActive("otro@example.com")
	_ = other
	plain := seedEmailRec(t, store, uid, "nuevo@example.com")
	// Otro registra nuevo@ antes de confirmar → race.
	store.users["nuevo@example.com"] = &emailChangeUser{id: uuid.NewString(), email: "nuevo@example.com", active: true}
	s, m, _ := emailConfirmSvc(store)
	_, err := s.Execute(context.Background(), EmailChangeConfirmInput{
		Token: plain, RequestID: uuid.NewString(),
	})
	if !errors.Is(err, user.ErrEmailAlreadyInUse) {
		t.Fatalf("race taken: %v", err)
	}
	if m.counts["confirm/taken"] != 1 {
		t.Fatalf("métrica: %v", m.counts)
	}
	// Token quemado: reintento → 400 (no 409).
	if _, err := s.Execute(context.Background(), EmailChangeConfirmInput{
		Token: plain, RequestID: uuid.NewString(),
	}); err == nil {
		t.Fatal("quemado 400")
	}
}

func TestEmailChangeConfirm_InvalidosYBearerAjeno(t *testing.T) {
	newStore := func() (*fakeEmailChangeStore, string) {
		st := newFakeEmailChangeStore()
		uid := st.seedActive("viejo@example.com")
		h, _ := user.ParseEmailChangeToken(strings.Repeat("A", 43))
		st.records[h] = &user.EmailChangeRecord{
			RequesterID: uid, TokenHash: h, NewNormalized: "nuevo@example.com",
			ExpiresAt: time.Now().UTC().Add(-time.Minute),
		}
		return st, uid
	}
	for name, in := range map[string]EmailChangeConfirmInput{
		"expirado":  {Token: strings.Repeat("A", 43), RequestID: uuid.NewString()},
		"aleatorio": {Token: strings.Repeat("B", 43), RequestID: uuid.NewString()},
		"malformado": {Token: "corto", RequestID: uuid.NewString()},
	} {
		st, _ := newStore()
		s, _, sleeps := emailConfirmSvc(st)
		_, err := s.Execute(context.Background(), in)
		if err == nil {
			t.Fatalf("%s: debía fallar", name)
		}
		if name != "malformado" {
			for _, d := range *sleeps {
				if d < 40*time.Millisecond || d > 80*time.Millisecond {
					t.Fatalf("delay 40-80ms: %v", d)
				}
			}
		}
	}
	// Bearer ajeno → 400 opaco (cuenta abuso).
	st, uid := newStore()
	st.records = map[string]*user.EmailChangeRecord{}
	plain := seedEmailRec(t, st, uid, "nuevo@example.com")
	s, _, _ := emailConfirmSvc(st)
	_, err := s.Execute(context.Background(), EmailChangeConfirmInput{
		Token: plain, RequestID: uuid.NewString(), BearerUserID: "otro", HasBearer: true,
	})
	if err == nil {
		t.Fatal("bearer ajeno 400")
	}
	if st.incrCalls != 1 {
		t.Fatal("abuso contado")
	}
	// Mismo requester con Bearer → 200.
	st2, uid2 := newStore()
	plain2 := seedEmailRec(t, st2, uid2, "nuevo@example.com")
	s2, _, _ := emailConfirmSvc(st2)
	out, err := s2.Execute(context.Background(), EmailChangeConfirmInput{
		Token: plain2, RequestID: uuid.NewString(), BearerUserID: uid2, HasBearer: true,
	})
	if err != nil || out.Status != "email_changed" {
		t.Fatalf("propio: %v %+v", err, out)
	}
}
