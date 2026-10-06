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

// --- Fakes CU-AUTH-06 ---

type fakeStepUpIssuer struct {
	n      int
	tokens map[string]auth.StepUpClaims
	fail   error
}

func newFakeStepUpIssuer() *fakeStepUpIssuer {
	return &fakeStepUpIssuer{tokens: map[string]auth.StepUpClaims{}}
}

func (f *fakeStepUpIssuer) IssueToken(_ context.Context, userID string, scope auth.StepUpScope, amr []string) (string, string, error) {
	if f.fail != nil {
		return "", "", f.fail
	}
	f.n++
	jti := "jti-" + string(rune('a'+f.n%26)) + uuid.NewString()
	now := time.Now().UTC()
	f.tokens["stup-"+jti] = auth.StepUpClaims{
		Iss: "https://auth.example.com", Aud: auth.StepUpAud,
		Sub: userID, JTI: jti, Scope: string(scope),
		Iat: now.Unix(), Exp: now.Add(auth.StepUpTokenTTL).Unix(),
		AuthTime: now.Unix(), AMR: amr,
	}
	return "stup-" + jti, jti, nil
}

func (f *fakeStepUpIssuer) VerifyToken(token string) (auth.StepUpClaims, error) {
	if c, ok := f.tokens[token]; ok {
		return c, nil
	}
	return auth.StepUpClaims{}, errors.New("bad token")
}

type fakeJTIStore struct {
	live         map[string][2]string // jti → {sub, scope}
	saveErr      error
	consumeErr   error
	saveCalls    int
	consumeCalls int
}

func newFakeJTIStore() *fakeJTIStore {
	return &fakeJTIStore{live: map[string][2]string{}}
}

func (f *fakeJTIStore) Save(_ context.Context, jti, sub, scope string) error {
	f.saveCalls++
	if f.saveErr != nil {
		return f.saveErr
	}
	f.live[jti] = [2]string{sub, scope}
	return nil
}

func (f *fakeJTIStore) Consume(_ context.Context, jti string) (string, string, bool, error) {
	f.consumeCalls++
	if f.consumeErr != nil {
		return "", "", false, f.consumeErr
	}
	v, ok := f.live[jti]
	if !ok {
		return "", "", false, nil
	}
	delete(f.live, jti)
	return v[0], v[1], true, nil
}

type stepHasher struct {
	ok  bool
	err error
}

func (h *stepHasher) Hash(_ context.Context, _ string) (string, error) {
	return "hash", nil
}
func (h *stepHasher) Verify(_ context.Context, _, _ string) (bool, error) {
	return h.ok, h.err
}

type stepMetrics struct {
	counts map[string]int
	reuse  int
}

func newStepMetrics() *stepMetrics                           { return &stepMetrics{counts: map[string]int{}} }
func (m *stepMetrics) IncStepUp(op, r string)                { m.counts[op+"/"+r]++ }
func (m *stepMetrics) ObserveStepUpDuration(string, float64) {}
func (m *stepMetrics) IncReuseBlocked()                      { m.reuse++ }

type stepUpFixture struct {
	svc     *StepUpService
	issuer  *fakeStepUpIssuer
	jtis    *fakeJTIStore
	tracker *fakeTracker
	chal    *fakeChal
	totp    *fakeTOTP
	secrets *fakeSecrets
	backup  *fakeBackupStore
	metrics *stepMetrics
	sleeps  *[]time.Duration
}

func newStepUpFixture(repo *mockRepo) *stepUpFixture {
	tracker := newFakeTracker()
	totp := newFakeTOTP()
	secrets := newFakeSecrets()
	chal := newFakeChal()
	backup := newFakeBackupStore()
	issuer := newFakeStepUpIssuer()
	jtis := newFakeJTIStore()
	metrics := newStepMetrics()
	s := NewStepUpService(repo, &stepHasher{ok: true}, tracker, totp, fakeBox{},
		secrets, chal, &fakeBackupIssuer{}, backup, issuer, jtis,
		&mockOutbox{}, newMockIdem(), mockAudit{}, metrics, NoopTracer{})
	var sleeps []time.Duration
	s.Sleep = func(d time.Duration) { sleeps = append(sleeps, d) }
	return &stepUpFixture{svc: s, issuer: issuer, jtis: jtis, tracker: tracker,
		chal: chal, totp: totp, secrets: secrets, backup: backup,
		metrics: metrics, sleeps: &sleeps}
}

func seedStepUpUser(repo *mockRepo, uid, email string, mfa bool, withPassword bool) {
	pw := ""
	if withPassword {
		pw = "$argon2id$v=19$m=65536,t=3,p=4$salt$hash"
	}
	repo.byEmail[email] = &user.User{ID: uid, EmailNormalized: email,
		EmailOriginal: email, PasswordHash: pw, Status: user.StatusActive, MFAEnabled: mfa}
}

func seedStepUpTOTP(f *stepUpFixture, uid string) string {
	raw := []byte("12345678901234567890")
	enc, _ := fakeBox{}.Encrypt(context.Background(), uid, raw)
	f.secrets.active[uid] = enc
	counter := auth.NewCounter(time.Now().UTC())
	f.totp.codes[counter] = "123456"
	return "123456"
}

func stepAuthUser(uid string, age time.Duration) AuthUser {
	return AuthUser{ID: uid, AuthTime: time.Now().UTC().Add(-age)}
}

func TestStepUpChallenge_PasswordOnly(t *testing.T) {
	repo := newMockRepo()
	uid := uuid.NewString()
	seedStepUpUser(repo, uid, "u@example.com", false, true)
	f := newStepUpFixture(repo)
	out, err := f.svc.Challenge(context.Background(), StepUpChallengeInput{
		User: stepAuthUser(uid, 30*time.Minute), Scope: string(auth.ScopeChangePassword),
		Password: "correcta", RequestID: uuid.NewString(),
	})
	if err != nil || out.Token == "" || out.Scope != string(auth.ScopeChangePassword) || out.ExpiresIn != 300 {
		t.Fatalf("err=%v out=%+v", err, out)
	}
	if f.jtis.saveCalls != 1 {
		t.Fatal("jti single-use guardado")
	}
	if f.metrics.counts["challenge/issued"] != 1 {
		t.Fatalf("métrica: %v", f.metrics.counts)
	}
}

func TestStepUpChallenge_BadPasswordIgualBadTOTP(t *testing.T) {
	mkSvc := func() (*stepUpFixture, string) {
		repo := newMockRepo()
		uid := uuid.NewString()
		seedStepUpUser(repo, uid, "u@example.com", true, true)
		f := newStepUpFixture(repo)
		f.svc.Hasher = &stepHasher{ok: false}
		seedStepUpTOTP(f, uid)
		return f, uid
	}
	// Password mala.
	f1, uid1 := mkSvc()
	_, err1 := f1.svc.Challenge(context.Background(), StepUpChallengeInput{
		User: stepAuthUser(uid1, time.Hour), Scope: string(auth.ScopeMFADisable),
		Password: "mala", Code: "123456", RequestID: uuid.NewString(),
	})
	// TOTP malo (password buena).
	f2, uid2 := mkSvc()
	_, err2 := f2.svc.Challenge(context.Background(), StepUpChallengeInput{
		User: stepAuthUser(uid2, time.Hour), Scope: string(auth.ScopeMFADisable),
		Password: "buena", Code: "000000", RequestID: uuid.NewString(),
	})
	if !errors.Is(err1, auth.ErrStepUpInvalid) || !errors.Is(err2, auth.ErrStepUpInvalid) {
		t.Fatalf("ambos 401 opaco: %v %v", err1, err2)
	}
	if err1.Error() != err2.Error() {
		t.Fatal("mismo error sin distinguir factor")
	}
	for i, f := range []*stepUpFixture{f1, f2} {
		if len(*f.sleeps) != 1 {
			t.Fatalf("[%d] un delay", i)
		}
		d := (*f.sleeps)[0]
		if d < 40*time.Millisecond || d > 80*time.Millisecond {
			t.Fatalf("[%d] delay 40-80ms: %v", i, d)
		}
	}
}

func TestStepUpChallenge_DobleOKBackupConsume(t *testing.T) {
	repo := newMockRepo()
	uid := uuid.NewString()
	seedStepUpUser(repo, uid, "u@example.com", true, true)
	f := newStepUpFixture(repo)
	// Registra un backup válido en el store.
	f.backup.hashes[uid] = []string{"hash:AB23EFGH45"}
	out, err := f.svc.Challenge(context.Background(), StepUpChallengeInput{
		User: stepAuthUser(uid, time.Hour), Scope: string(auth.ScopeBackupRegen),
		Password: "ok", Code: "AB23-EFGH45", RequestID: uuid.NewString(),
	})
	if err != nil || out.Token == "" {
		t.Fatalf("err=%v out=%+v", err, out)
	}
}

func TestStepUpChallenge_FederatedStaleRelogin(t *testing.T) {
	repo := newMockRepo()
	uid := uuid.NewString()
	seedStepUpUser(repo, uid, "f@example.com", false, false) // federated-only
	f := newStepUpFixture(repo)
	_, err := f.svc.Challenge(context.Background(), StepUpChallengeInput{
		User: stepAuthUser(uid, time.Hour), Scope: string(auth.ScopeFederatedUnlink),
		RequestID: uuid.NewString(),
	})
	if !errors.Is(err, auth.ErrStepUpRelogin) {
		t.Fatalf("relogin, got %v", err)
	}
}

func TestStepUpChallenge_UnknownScopeYValidacion(t *testing.T) {
	repo := newMockRepo()
	uid := uuid.NewString()
	seedStepUpUser(repo, uid, "u@example.com", false, true)
	f := newStepUpFixture(repo)
	if _, err := f.svc.Challenge(context.Background(), StepUpChallengeInput{
		User: stepAuthUser(uid, time.Hour), Scope: "admin",
		Password: "x", RequestID: uuid.NewString(),
	}); !errors.Is(err, auth.ErrUnknownScope) {
		t.Fatalf("scope: %v", err)
	}
	if _, err := f.svc.Challenge(context.Background(), StepUpChallengeInput{
		User: stepAuthUser(uid, time.Hour), Scope: string(auth.ScopeChangePassword),
		RequestID: uuid.NewString(),
	}); err == nil {
		t.Fatal("password requerida → 400")
	}
}

func TestStepUpChallenge_LockTrasFails(t *testing.T) {
	repo := newMockRepo()
	uid := uuid.NewString()
	seedStepUpUser(repo, uid, "u@example.com", false, true)
	f := newStepUpFixture(repo)
	f.svc.Hasher = &stepHasher{ok: false}
	in := StepUpChallengeInput{
		User: stepAuthUser(uid, time.Hour), Scope: string(auth.ScopeChangeEmail),
		Password: "mala",
	}
	for i := 0; i < 5; i++ {
		in.RequestID = uuid.NewString()
		if _, err := f.svc.Challenge(context.Background(), in); !errors.Is(err, auth.ErrStepUpInvalid) {
			t.Fatalf("fail %d: %v", i, err)
		}
	}
	// 6º con buena → 401 por lock (sin token).
	f.svc.Hasher = &stepHasher{ok: true}
	in.RequestID = uuid.NewString()
	in.Password = "buena"
	if _, err := f.svc.Challenge(context.Background(), in); !errors.Is(err, auth.ErrStepUpInvalid) {
		t.Fatalf("lock: %v", err)
	}
}

func TestStepUpChallenge_Idempotente60s(t *testing.T) {
	repo := newMockRepo()
	uid := uuid.NewString()
	seedStepUpUser(repo, uid, "u@example.com", false, true)
	f := newStepUpFixture(repo)
	reqID := uuid.NewString()
	in := StepUpChallengeInput{
		User: stepAuthUser(uid, time.Hour), Scope: string(auth.ScopeAPIKeysWrite),
		Password: "ok", RequestID: reqID,
	}
	out1, err := f.svc.Challenge(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	out2, err := f.svc.Challenge(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if out1.Token != out2.Token || f.issuer.n != 1 {
		t.Fatal("mismo RequestID → mismo token sin re-emitir")
	}
}

func TestStepUpGuard_FastPassSinRedis(t *testing.T) {
	repo := newMockRepo()
	f := newStepUpFixture(repo)
	f.svc.JTIs = nil // ni Redis haría falta
	f.svc.Tokens = nil
	mode, err := f.svc.Check(context.Background(), "u1",
		time.Now().UTC().Add(-time.Minute), auth.ScopeFederatedUnlink, "")
	if err != nil || mode != StepUpFastPass {
		t.Fatalf("fast_pass offline: %v %q", err, mode)
	}
}

func TestStepUpGuard_StaleSinTokenRequired(t *testing.T) {
	repo := newMockRepo()
	f := newStepUpFixture(repo)
	if _, err := f.svc.Check(context.Background(), "u1",
		time.Now().UTC().Add(-time.Hour), auth.ScopeAccountDelete, ""); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("required: %v", err)
	}
}

func TestStepUpGuard_TokenUnUsoUnScope(t *testing.T) {
	repo := newMockRepo()
	f := newStepUpFixture(repo)
	uid := uuid.NewString()
	tok, jti, _ := f.issuer.IssueToken(context.Background(), uid, auth.ScopeChangePassword, []string{"pwd"})
	// El flujo real hace Save al emitir; aquí lo simulamos.
	if err := f.jtis.Save(context.Background(), jti, uid, string(auth.ScopeChangePassword)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Check(context.Background(), uid,
		time.Now().UTC().Add(-time.Hour), auth.ScopeChangePassword, "forjado"); !errors.Is(err, auth.ErrStepUpInvalid) {
		t.Fatalf("forjado inválido: %v", err)
	}
	mode, err := f.svc.Check(context.Background(), uid,
		time.Now().UTC().Add(-time.Hour), auth.ScopeChangePassword, tok)
	if err != nil || mode != StepUpToken {
		t.Fatalf("token ok: %v %q", err, mode)
	}
	// Replay → REUSED (código distinto).
	if _, err := f.svc.Check(context.Background(), uid,
		time.Now().UTC().Add(-time.Hour), auth.ScopeChangePassword, tok); !errors.Is(err, auth.ErrStepUpReused) {
		t.Fatalf("reused: %v", err)
	}
	if f.metrics.reuse != 1 {
		t.Fatal("reuse_blocked metric")
	}
	// Otra scope → INVALID.
	tok2, _, _ := f.issuer.IssueToken(context.Background(), uid, auth.ScopeChangeEmail, []string{"pwd"})
	if _, err := f.svc.Check(context.Background(), uid,
		time.Now().UTC().Add(-time.Hour), auth.ScopeChangePassword, tok2); !errors.Is(err, auth.ErrStepUpInvalid) {
		t.Fatalf("cross-scope: %v", err)
	}
	// Sub distinto → INVALID.
	if _, err := f.svc.Check(context.Background(), "otro",
		time.Now().UTC().Add(-time.Hour), auth.ScopeChangeEmail, tok2); !errors.Is(err, auth.ErrStepUpInvalid) {
		t.Fatalf("cross-sub: %v", err)
	}
}

func TestStepUpGuard_RedisDownFailClosed(t *testing.T) {
	repo := newMockRepo()
	f := newStepUpFixture(repo)
	f.jtis.consumeErr = errors.New("redis down")
	tok, _, _ := f.issuer.IssueToken(context.Background(), "u1", auth.ScopeRolesChange, []string{"pwd"})
	if _, err := f.svc.Check(context.Background(), "u1",
		time.Now().UTC().Add(-time.Hour), auth.ScopeRolesChange, tok); !errors.Is(err, auth.ErrStepUpUnavailable) {
		t.Fatalf("fail-closed: %v", err)
	}
	// Fast-pass sigue 200 sin Redis.
	if mode, err := f.svc.Check(context.Background(), "u1",
		time.Now().UTC().Add(-time.Minute), auth.ScopeRolesChange, tok); err != nil || mode != StepUpFastPass {
		t.Fatalf("fast-pass: %v %q", err, mode)
	}
}

func TestStepUpChallenge_RedisDownUnavailable(t *testing.T) {
	repo := newMockRepo()
	uid := uuid.NewString()
	seedStepUpUser(repo, uid, "u@example.com", false, true)
	f := newStepUpFixture(repo)
	f.jtis.saveErr = errors.New("redis down")
	_, err := f.svc.Challenge(context.Background(), StepUpChallengeInput{
		User: stepAuthUser(uid, time.Hour), Scope: string(auth.ScopeChangePassword),
		Password: "ok", RequestID: uuid.NewString(),
	})
	if !errors.Is(err, auth.ErrStepUpUnavailable) {
		t.Fatalf("fail-closed: %v", err)
	}
}

func TestStepUpChallenge_NonActive403(t *testing.T) {
	repo := newMockRepo()
	uid := uuid.NewString()
	repo.byEmail["p@example.com"] = &user.User{ID: uid, EmailNormalized: "p@example.com",
		Status: user.StatusPendingVerification, PasswordHash: "h"}
	f := newStepUpFixture(repo)
	_, err := f.svc.Challenge(context.Background(), StepUpChallengeInput{
		User: stepAuthUser(uid, time.Hour), Scope: string(auth.ScopeChangePassword),
		Password: "x", RequestID: uuid.NewString(),
	})
	if !errors.Is(err, auth.ErrAccountUnavailable) {
		t.Fatalf("no-active: %v", err)
	}
}

func TestStepUpReplayToken(t *testing.T) {
	tok, ok := stepUpReplayToken("cred:change-password\nstup-x", "cred:change-password")
	if !ok || tok != "stup-x" {
		t.Fatalf("got %q %v", tok, ok)
	}
	if _, ok := stepUpReplayToken("cred:change-password\nstup-x", "mfa:disable"); ok {
		t.Fatal("scope distinto no reutiliza")
	}
	if _, ok := stepUpReplayToken("sin-separador", "x"); ok {
		t.Fatal("forma inválida")
	}
}
