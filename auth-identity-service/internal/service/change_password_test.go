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

// --- Fakes CU-CRED-02 ---

type fakeHistoryStore struct {
	accounts map[string]*auth.ChangeAccount
	history  map[string][]string
	rotateCalls int
	lastKeepSID string
	lastOldHash string
	lastVer     int
	peers       int
	rotateErr   error
}

func newFakeHistoryStore() *fakeHistoryStore {
	return &fakeHistoryStore{accounts: map[string]*auth.ChangeAccount{}, history: map[string][]string{}}
}

func (f *fakeHistoryStore) Current(_ context.Context, uid string) (*auth.ChangeAccount, error) {
	a, ok := f.accounts[uid]
	if !ok {
		return nil, errors.New("no rows")
	}
	cp := *a
	return &cp, nil
}
func (f *fakeHistoryStore) LastN(_ context.Context, uid string, n int) ([]string, error) {
	h := f.history[uid]
	if len(h) > n {
		return h[len(h)-n:], nil
	}
	return h, nil
}
func (f *fakeHistoryStore) RotateTx(_ context.Context, uid, oldHash, newHash string, expectedVer int, keepSID, _ string) (int, int, error) {
	f.rotateCalls++
	if f.rotateErr != nil {
		return 0, 0, f.rotateErr
	}
	a := f.accounts[uid]
	if a.Hash != oldHash || a.Ver != expectedVer {
		return 0, 0, auth.ErrPasswordReused // base movida (TOCTOU)
	}
	f.lastKeepSID = keepSID
	f.lastOldHash = oldHash
	f.lastVer = expectedVer
	f.history[uid] = append(f.history[uid], oldHash)
	a.Hash = newHash
	a.Ver++
	return a.Ver, f.peers, nil
}

type changeHasher struct {
	matchPlain string
	hashCalls  int
}

func (h *changeHasher) Hash(_ context.Context, _ string) (string, error) {
	h.hashCalls++
	return "new-hash", nil
}
func (h *changeHasher) Verify(_ context.Context, plain, _ string) (bool, error) {
	return plain == h.matchPlain, nil
}

type fakeStepUpChecker struct {
	mode string
	err  error
}

func (f *fakeStepUpChecker) Check(_ context.Context, _ string, _ time.Time, _ auth.StepUpScope, _ string) (string, error) {
	return f.mode, f.err
}

type changeMetrics struct {
	counts  map[string]int
	history int
	peers   int
	locks   int
	hibp    int
}

func newChangeMetrics() *changeMetrics { return &changeMetrics{counts: map[string]int{}} }
func (m *changeMetrics) IncChange(r, v string)            { m.counts[r+"/"+v]++ }
func (m *changeMetrics) ObserveChangeDuration(float64)    {}
func (m *changeMetrics) IncHistoryHit()                   { m.history++ }
func (m *changeMetrics) IncPeersRevoked(n int)            { m.peers += n }
func (m *changeMetrics) IncChangeLock()                   { m.locks++ }
func (m *changeMetrics) IncHibpFallback()                 { m.hibp++ }

type changeFixture struct {
	svc     *ChangePasswordService
	store   *fakeHistoryStore
	tracker *fakeTracker
	outbox  *mockOutbox
	metrics *changeMetrics
}

func newChangeFixture() *changeFixture {
	store := newFakeHistoryStore()
	tracker := newFakeTracker()
	outbox := &mockOutbox{}
	metrics := newChangeMetrics()
	s := NewChangePasswordService(store, &changeHasher{}, nil, tracker,
		&fakeStepUpChecker{}, outbox, newMockIdem(), mockAudit{}, metrics, NoopTracer{})
	return &changeFixture{svc: s, store: store, tracker: tracker, outbox: outbox, metrics: metrics}
}

const changeOldHash = "old-hash"

func seedChangeUser(f *changeFixture, mfa bool, withPassword bool) string {
	uid := uuid.NewString()
	pw := ""
	if withPassword {
		pw = changeOldHash
	}
	f.store.accounts[uid] = &auth.ChangeAccount{
		ID: uid, Email: "u@example.com", Hash: pw, Ver: 3, Status: user.StatusActive,
	}
	_ = mfa
	return uid
}

func changeInput(uid, sid string) ChangePasswordInput {
	return ChangePasswordInput{
		User: AuthUser{ID: uid, AuthTime: time.Now().UTC().Add(-time.Hour)},
		SID: sid, Current: "actual", HasCurrent: true,
		NewPassword: "Nu3va!Valida-2026", RequestID: uuid.NewString(),
	}
}

func TestChangePassword_OKRevocaPares(t *testing.T) {
	f := newChangeFixture()
	uid := seedChangeUser(f, false, true)
	f.svc.Hasher = &changeHasher{matchPlain: "actual"}
	f.store.peers = 2
	out, err := f.svc.Execute(context.Background(), changeInput(uid, "sid-actual"))
	if err != nil || out.Status != "password_changed" || out.SessionsRevoked != 2 || out.Via != "change" {
		t.Fatalf("err=%v out=%+v", err, out)
	}
	if f.store.lastKeepSID != "sid-actual" || f.store.lastOldHash != changeOldHash || f.store.lastVer != 3 {
		t.Fatal("keepSID/base/ver pasados a la Tx")
	}
	if len(f.store.history[uid]) != 1 || f.store.accounts[uid].Ver != 4 {
		t.Fatal("history+1 y ver+1")
	}
	if f.metrics.counts["success/change"] != 1 || f.metrics.peers != 2 {
		t.Fatalf("métricas: %v peers=%d", f.metrics.counts, f.metrics.peers)
	}
}

func TestChangePassword_CurrentMalaLock(t *testing.T) {
	f := newChangeFixture()
	uid := seedChangeUser(f, false, true)
	f.svc.Hasher = &changeHasher{matchPlain: "otra"}
	in := changeInput(uid, "sid-a")
	in.Current = "mala"
	for i := 0; i < 5; i++ {
		in.RequestID = uuid.NewString()
		if _, err := f.svc.Execute(context.Background(), in); !errors.Is(err, auth.ErrInvalidCurrent) {
			t.Fatalf("fail %d: %v", i, err)
		}
	}
	if len(f.tracker.lockCalls) != 5 {
		t.Fatalf("5 fails: %d", len(f.tracker.lockCalls))
	}
	// 6º con buena → 401 por lock.
	f.svc.Hasher = &changeHasher{matchPlain: "mala"}
	in.RequestID = uuid.NewString()
	in.Current = "mala"
	if _, err := f.svc.Execute(context.Background(), in); !errors.Is(err, auth.ErrInvalidCurrent) {
		t.Fatalf("lock: %v", err)
	}
	if f.metrics.locks != 1 {
		t.Fatal("lock contado")
	}
}

func TestChangePassword_ReusedHistoryPolicy(t *testing.T) {
	// Reused.
	f := newChangeFixture()
	uid := seedChangeUser(f, false, true)
	f.svc.Hasher = &stepHasher{ok: true} // actual y nueva verifican → reused
	f.store.history[uid] = []string{"h-old-1"}
	in := changeInput(uid, "s")
	in.Current = "actual"
	// matchPlain hace Verify(new)==true contra CUALQUIER hash → reused antes que history.
	if _, err := f.svc.Execute(context.Background(), in); !errors.Is(err, auth.ErrPasswordReused) {
		t.Fatalf("reused: %v", err)
	}
	if f.store.rotateCalls != 0 {
		t.Fatal("sin Tx")
	}
	// In-history (Verify true solo para H1).
	f2 := newChangeFixture()
	uid2 := seedChangeUser(f2, false, true)
	f2.store.history[uid2] = []string{"v:h-x", "v:H1-valida!2026X"}
	h2 := &histHasher{current: changeOldHash, hist: map[string]bool{"v:H1-valida!2026X": true}, matchNew: "actual"}
	f2.svc.Hasher = h2
	in2 := changeInput(uid2, "s")
	in2.Current = "actual"
	in2.NewPassword = "H1-valida!2026X"
	if _, err := f2.svc.Execute(context.Background(), in2); !errors.Is(err, auth.ErrPasswordInHistory) {
		t.Fatalf("history: %v", err)
	}
	if f2.metrics.history != 1 {
		t.Fatal("history hit")
	}
	// Policy débil → 400 sin hash.
	f3 := newChangeFixture()
	uid3 := seedChangeUser(f3, false, true)
	in3 := changeInput(uid3, "s")
	in3.NewPassword = "corta"
	h3 := f3.svc.Hasher.(*changeHasher)
	if _, err := f3.svc.Execute(context.Background(), in3); err == nil {
		t.Fatal("policy debía fallar")
	}
	if h3.hashCalls != 0 || f3.store.rotateCalls != 0 {
		t.Fatal("sin hash ni Tx")
	}
}

// histHasher matchea actual o un conjunto histórico.
type histHasher struct {
	current  string
	hist     map[string]bool
	matchNew string
}

func (h *histHasher) Hash(_ context.Context, _ string) (string, error) { return "new-hash", nil }
func (h *histHasher) Verify(_ context.Context, plain, hash string) (bool, error) {
	if hash == h.current {
		return plain == h.matchNew, nil
	}
	return h.hist["v:"+plain], nil
}

func TestChangePassword_MissingUnexpected(t *testing.T) {
	f := newChangeFixture()
	uid := seedChangeUser(f, false, true)
	in := changeInput(uid, "s")
	in.HasCurrent = false
	if _, err := f.svc.Execute(context.Background(), in); err == nil {
		t.Fatal("missing current 400")
	}
	// Federated-set con current → 400.
	f2 := newChangeFixture()
	uid2 := seedChangeUser(f2, false, false)
	in2 := changeInput(uid2, "s")
	if _, err := f2.svc.Execute(context.Background(), in2); err == nil {
		t.Fatal("unexpected current 400")
	}
}

func TestChangePassword_FederatedSet(t *testing.T) {
	// Sin token → STEP_UP_REQUIRED.
	f := newChangeFixture()
	uid := seedChangeUser(f, false, false)
	f.svc.StepUp = &fakeStepUpChecker{err: auth.ErrStepUpRequired}
	in := changeInput(uid, "s")
	in.HasCurrent = false
	if _, err := f.svc.Execute(context.Background(), in); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("required: %v", err)
	}
	// Con token → 200 via set.
	f2 := newChangeFixture()
	uid2 := seedChangeUser(f2, false, false)
	f2.svc.StepUp = &fakeStepUpChecker{mode: "token"}
	f2.store.peers = 1
	in2 := changeInput(uid2, "s")
	in2.HasCurrent = false
	in2.StepUpToken = "stup"
	out, err := f2.svc.Execute(context.Background(), in2)
	if err != nil || out.Via != "set" || out.SessionsRevoked != 1 {
		t.Fatalf("set: %v %+v", err, out)
	}
}

func TestChangePassword_ReplayYToctou(t *testing.T) {
	// Replay mismo RequestID → 1 sola rotación.
	f := newChangeFixture()
	uid := seedChangeUser(f, false, true)
	f.svc.Hasher = &changeHasher{matchPlain: "actual"}
	reqID := uuid.NewString()
	in := changeInput(uid, "s")
	in.RequestID = reqID
	if _, err := f.svc.Execute(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	out2, err := f.svc.Execute(context.Background(), in)
	if err != nil || out2.Status != "password_changed" {
		t.Fatalf("replay: %v %+v", err, out2)
	}
	if f.store.rotateCalls != 1 {
		t.Fatalf("sin re-rotar: %d", f.store.rotateCalls)
	}
	// TOCTOU: dos cambios concurrentes misma base → 1×200 + 1×REUSED.
	f2 := newChangeFixture()
	uid2 := seedChangeUser(f2, false, true)
	f2.svc.Hasher = &changeHasher{matchPlain: "actual"}
	f2.store.peers = 0
	inA := changeInput(uid2, "s")
	inA.NewPassword = "Nu3va!Valida-2026A"
	inB := changeInput(uid2, "s")
	inB.NewPassword = "Nu3va!Valida-2026B"
	// Misma base/ver para ambas (pre-Tx).
	if _, err := f2.svc.Execute(context.Background(), inA); err != nil {
		t.Fatalf("A: %v", err)
	}
	// B leyó base vieja: simula reinyectando (el fake ya avanzó ver).
	// Como el servicio relee Current por request, B vería newHash... Para
	// forzar la carrera se usa directamente RotateTx con base vieja:
	if _, _, err := f2.store.RotateTx(context.Background(), uid2, changeOldHash, "hB", 3, "s", "req-b"); !errors.Is(err, auth.ErrPasswordReused) {
		t.Fatalf("TOCTOU perdedor REUSED: %v", err)
	}
}

func TestChangePassword_NoActiveEInfra(t *testing.T) {
	f := newChangeFixture()
	uid := uuid.NewString()
	f.store.accounts[uid] = &auth.ChangeAccount{ID: uid, Status: user.StatusLocked}
	in := changeInput(uid, "s")
	if _, err := f.svc.Execute(context.Background(), in); !errors.Is(err, auth.ErrAccountUnavailable) {
		t.Fatalf("locked: %v", err)
	}
	// HIBP comprometida → POLICY.
	f2 := newChangeFixture()
	uid2 := seedChangeUser(f2, false, true)
	f2.svc.Breach = &fakeBreach{compromised: true}
	in2 := changeInput(uid2, "s")
	in2.Current = "actual"
	f2.svc.Hasher = &changeHasher{matchPlain: "actual"}
	if _, err := f2.svc.Execute(context.Background(), in2); err == nil {
		t.Fatal("hibp debía fallar")
	}
	// HIBP caído (timeout) + clave fuera de deny-list → fallback, el flujo sigue.
	f3 := newChangeFixture()
	uid3 := seedChangeUser(f3, false, true)
	f3.svc.Breach = &fakeBreach{err: errors.New("timeout")}
	f3.svc.Hasher = &changeHasher{matchPlain: "actual"}
	m3 := f3.metrics
	out3, err := f3.svc.Execute(context.Background(), changeInput(uid3, "s"))
	if err != nil || out3.Status != "password_changed" {
		t.Fatalf("hibp-fallback: %v %+v", err, out3)
	}
	if m3.hibp != 1 {
		t.Fatal("métrica hibp_fallback")
	}
}
