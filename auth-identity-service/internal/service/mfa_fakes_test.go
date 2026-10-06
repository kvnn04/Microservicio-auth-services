package service

import (
	"context"
	"errors"
	"time"

	"auth-identity-service/internal/domain/auth"
	"auth-identity-service/internal/domain/user"
)

type fakeTOTP struct {
	secret []byte
	codes  map[int64]string // counter -> code válido
}

func newFakeTOTP() *fakeTOTP {
	return &fakeTOTP{secret: []byte("12345678901234567890"), codes: map[int64]string{}}
}
func (f *fakeTOTP) GenerateSecret(_ context.Context) ([]byte, string, error) {
	return f.secret, "GEZDGNBVGY3TQOJQ", nil
}
func (f *fakeTOTP) CodeAt(_ context.Context, _ []byte, _ int64) (string, error) {
	return "123456", nil
}
func (f *fakeTOTP) Validate(_ context.Context, _ []byte, code string, counter int64) (int64, bool) {
	for _, c := range auth.Candidates(counter) {
		if v, ok := f.codes[c]; ok && v == code {
			return c, true
		}
	}
	return 0, false
}

type fakeBox struct{}

func (fakeBox) Encrypt(_ context.Context, _ string, raw []byte) ([]byte, error) {
	return append([]byte("enc:"), raw...), nil
}
func (fakeBox) Decrypt(_ context.Context, _ string, sealed []byte) ([]byte, error) {
	return sealed[len("enc:"):], nil
}

type fakeSecrets struct {
	staged  map[string][]byte
	active  map[string][]byte
	expired map[string]bool
}

func newFakeSecrets() *fakeSecrets {
	return &fakeSecrets{staged: map[string][]byte{}, active: map[string][]byte{}, expired: map[string]bool{}}
}
func (f *fakeSecrets) Stage(_ context.Context, uid string, enc []byte) error {
	f.staged[uid] = enc
	return nil
}
func (f *fakeSecrets) Staged(_ context.Context, uid string) ([]byte, bool, error) {
	enc, ok := f.staged[uid]
	if !ok {
		return nil, false, auth.ErrNoStaged
	}
	return enc, f.expired[uid], nil
}
func (f *fakeSecrets) PromoteTx(_ context.Context, uid string) error {
	f.active[uid] = f.staged[uid]
	delete(f.staged, uid)
	return nil
}
func (f *fakeSecrets) GetActive(_ context.Context, uid string) ([]byte, error) {
	if enc, ok := f.active[uid]; ok {
		return enc, nil
	}
	return nil, user.ErrNotFound
}
func (f *fakeSecrets) DisableTx(_ context.Context, uid string) error {
	delete(f.active, uid)
	return nil
}

type fakeChal struct {
	live     map[string]string // challengeID -> userID
	fails    map[string]int
	used     map[string]bool
	denyNext bool
	burned   map[string]bool
}

func newFakeChal() *fakeChal {
	return &fakeChal{live: map[string]string{}, fails: map[string]int{}, used: map[string]bool{}, burned: map[string]bool{}}
}
func (f *fakeChal) Register(_ context.Context, cid, uid string) error {
	f.live[cid] = uid
	return nil
}
func (f *fakeChal) Consume(_ context.Context, cid string) (string, error) {
	uid, ok := f.live[cid]
	if !ok {
		return "", user.ErrNotFound
	}
	delete(f.live, cid)
	return uid, nil
}
func (f *fakeChal) RecordFail(_ context.Context, cid string) (bool, error) {
	f.fails[cid]++
	if f.fails[cid] >= 5 {
		f.burned[cid] = true
		delete(f.live, cid) // quema: single-use revocado + denylist lógica
		return true, nil
	}
	return false, nil
}
func (f *fakeChal) MarkReplay(_ context.Context, uid string, counter int64) (bool, error) {
	if f.denyNext {
		return false, errors.New("stores down")
	}
	k := uid + "/" + itoa(counter)
	if f.used[k] {
		return false, nil
	}
	f.used[k] = true
	return true, nil
}
func (f *fakeChal) Uncheckable(_ context.Context) bool { return false }

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

type fakePreToken struct {
	claims auth.PreTokenClaims
	err    error
}

func (f *fakePreToken) ValidateChallenge(_ string) (auth.PreTokenClaims, error) {
	if f.err != nil {
		return auth.PreTokenClaims{}, f.err
	}
	return f.claims, nil
}

type fakeBackupIssuer struct{ n int }

func (f *fakeBackupIssuer) Generate(_ context.Context) (string, string, error) {
	f.n++
	return "ABCD-EFGH" + string(rune('A'+f.n%26)) + string(rune('A'+(f.n/26)%26)), "hash" + itoa(int64(f.n)), nil
}
func (f *fakeBackupIssuer) Hash(canonical string) string { return "hash:" + canonical }
func (f *fakeBackupIssuer) HashPrev(canonical string) (string, bool) {
	return "prev:" + canonical, true
}
func (f *fakeBackupIssuer) Verify(_ context.Context, _, _ string) bool { return true }

type fakeBackupStore struct {
	hashes     map[string][]string
	consumeErr error
	remaining  int
}

func newFakeBackupStore() *fakeBackupStore {
	return &fakeBackupStore{hashes: map[string][]string{}, remaining: 10}
}
func (f *fakeBackupStore) GenerateTx(_ context.Context, uid string, hashes []string, _ bool) (int, error) {
	f.hashes[uid] = append(f.hashes[uid], hashes...)
	return 0, nil
}
func (f *fakeBackupStore) ConsumeTx(_ context.Context, _ string, _ string, _ string) (int, error) {
	if f.consumeErr != nil {
		return 0, f.consumeErr
	}
	f.remaining--
	return f.remaining, nil
}
func (f *fakeBackupStore) CountRemaining(_ context.Context, _ string) (int, error) {
	return f.remaining, nil
}
func (f *fakeBackupStore) BurnAll(_ context.Context, _ string) error { return nil }

type fakeMFAMetrics struct{ counts map[string]int }

func newFakeMFAMetrics() *fakeMFAMetrics { return &fakeMFAMetrics{counts: map[string]int{}} }
func (m *fakeMFAMetrics) IncMFA(op, r string)         { m.counts[op+"/"+r]++ }
func (m *fakeMFAMetrics) ObserveVerifyDuration(float64) {}
func (m *fakeMFAMetrics) IncChallengeBurned(r string) { m.counts["burn/"+r]++ }
func (m *fakeMFAMetrics) IncReplayBlocked()           { m.counts["replay"]++ }

func freshAuthUser(id string) AuthUser {
	return AuthUser{ID: id, AuthTime: time.Now().UTC().Add(-time.Minute)}
}

func mfaSvc() (*MFAService, *fakeSecrets, *fakeChal, *fakeTOTP) {
	totp := newFakeTOTP()
	secrets := newFakeSecrets()
	chal := newFakeChal()
	repo := newMockRepo()
	s := NewMFAService(totp, fakeBox{}, secrets, chal,
		&fakePreToken{}, &fakeBackupIssuer{}, newFakeBackupStore(), repo, nil,
		&fakeSessions{}, &mockOutbox{}, newMockIdem(), mockAudit{},
		newFakeMFAMetrics(), NoopTracer{}, "Example")
	s.Sleep = func(time.Duration) {}
	return s, secrets, chal, totp
}

func seedMFAUser(repo *mockRepo, email, id string) {
	repo.byEmail[email] = &user.User{ID: id, EmailNormalized: email, Status: user.StatusActive,
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=4$salt$hash"}
}
