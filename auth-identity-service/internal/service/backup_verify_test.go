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

func backupSvc(store *fakeBackupStore) (*MFAService, *fakeChal) {
	totp := newFakeTOTP()
	secrets := newFakeSecrets()
	chal := newFakeChal()
	repo := newMockRepo()
	s := NewMFAService(totp, fakeBox{}, secrets, chal,
		&fakePreToken{}, &fakeBackupIssuer{}, store, repo, nil,
		&fakeSessions{}, &mockOutbox{}, newMockIdem(), mockAudit{},
		newFakeMFAMetrics(), NoopTracer{}, "Example")
	s.Sleep = func(time.Duration) {}
	return s, chal
}

func TestBackupGenerateConsume(t *testing.T) {
	store := newFakeBackupStore()
	s, _ := backupSvc(store)
	uid := uuid.NewString()
	plains, _, err := s.generateBackupSet(context.Background(), uid, false)
	if err != nil || len(plains) != 10 {
		t.Fatalf("generate: %v %d", err, len(plains))
	}
	seen := map[string]bool{}
	for _, p := range plains {
		if seen[p] {
			t.Fatal("duplicado en memoria")
		}
		seen[p] = true
	}
	if len(store.hashes[uid]) != 10 {
		t.Fatalf("hashes: %d", len(store.hashes[uid]))
	}
}

func TestBackupVerifyOKReuso401(t *testing.T) {
	store := newFakeBackupStore()
	s, chal := backupSvc(store)
	uid := uuid.NewString()
	// Pre-token + challenge vivo.
	chal.live["ch-b"] = uid
	s.PreToken = &fakePreToken{claims: auth.PreTokenClaims{Sub: uid, ChallengeID: "ch-b"}}
	// El fake store consume cualquier hash una vez (remaining decrece).
	in := VerifyInput{MFAToken: "tok", Code: "K7Q2-M9XD4P", RequestID: uuid.NewString()}
	out, err := s.Verify(context.Background(), in)
	if err != nil || out.Status != "active" || out.Method != "backup" {
		t.Fatalf("consume: %v %+v", err, out)
	}
	if out.Remaining != 9 {
		t.Fatalf("remaining=%d", out.Remaining)
	}
	// Reuso mismo código con challenge NUEVO → el fake ya lo consumió... el
	// fake no rastrea por hash; simula miss en 2º uso.
	store.consumeErr = auth.ErrBackupUsed
	chal.live["ch-b2"] = uid
	s.PreToken = &fakePreToken{claims: auth.PreTokenClaims{Sub: uid, ChallengeID: "ch-b2"}}
	in2 := VerifyInput{MFAToken: "tok2", Code: "K7Q2-M9XD4P", RequestID: uuid.NewString()}
	if _, err := s.Verify(context.Background(), in2); !errors.Is(err, auth.ErrInvalidMFA) {
		t.Fatalf("reuso: %v", err)
	}
	_ = user.StatusActive
}

func TestBackupMissIgualTOTP(t *testing.T) {
	store := newFakeBackupStore()
	store.consumeErr = auth.ErrBackupNotFound
	s, chal := backupSvc(store)
	uid := uuid.NewString()
	chal.live["ch-m"] = uid
	s.PreToken = &fakePreToken{claims: auth.PreTokenClaims{Sub: uid, ChallengeID: "ch-m"}}
	in := VerifyInput{MFAToken: "tok", Code: "ZZZZ-ZZZZZZ", RequestID: uuid.NewString()}
	_, err := s.Verify(context.Background(), in)
	if !errors.Is(err, auth.ErrInvalidMFA) {
		t.Fatalf("miss: %v", err)
	}
	// TOTP malo con challenge fresco → mismo error opaco.
	chal.live["ch-t"] = uid
	s.PreToken = &fakePreToken{claims: auth.PreTokenClaims{Sub: uid, ChallengeID: "ch-t"}}
	in2 := VerifyInput{MFAToken: "tok2", Code: "000000", RequestID: uuid.NewString()}
	_, err2 := s.Verify(context.Background(), in2)
	if !errors.Is(err2, auth.ErrInvalidMFA) {
		t.Fatalf("totp malo: %v", err2)
	}
}

func TestRegenerateSupersede(t *testing.T) {
	store := newFakeBackupStore()
	s, _ := backupSvc(store)
	uid := uuid.NewString()
	repo := s.Users.(*mockRepo)
	seedMFAUser(repo, "r@example.com", uid)
	s.Secrets.(*fakeSecrets).active[uid] = []byte("enc:x")
	out, err := s.Regenerate(context.Background(), RegenerateInput{
		User: freshAuthUser(uid), RequestID: uuid.NewString(),
	})
	if err != nil || len(out.Codes) != 10 || out.Remaining != 10 {
		t.Fatalf("regen: %v %+v", err, out)
	}
	// Stale → 401 sin quemar.
	_, err = s.Regenerate(context.Background(), RegenerateInput{
		User: AuthUser{ID: uid, AuthTime: time.Now().UTC().Add(-30 * time.Minute)},
		RequestID: uuid.NewString(),
	})
	if !errors.Is(err, user.ErrStepUpRequired) {
		t.Fatalf("stale: %v", err)
	}
}
