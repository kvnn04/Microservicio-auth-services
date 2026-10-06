package service

import (
	"context"
	"testing"

	"auth-identity-service/internal/domain/user"

	"github.com/google/uuid"
)

func resendSvc(store *mockVerifyStore, repo *mockRepo) *ResendService {
	if repo == nil {
		repo = newMockRepo()
	}
	return NewResendService(repo, store, mockPairIssuer{}, newMockIdem(), mockAudit{}, &mockVerifyMetrics{}, NoopTracer{})
}

func seedPending(repo *mockRepo, email, id string) *user.User {
	u := &user.User{ID: id, EmailNormalized: email, EmailOriginal: email, Status: user.StatusPendingVerification}
	repo.byEmail[email] = u
	return u
}

func TestResendQueued(t *testing.T) {
	repo := newMockRepo()
	store := newMockVerifyStore()
	seedPending(repo, "test@example.com", uuid.NewString())
	s := resendSvc(store, repo)
	out, err := s.Execute(context.Background(), ResendInput{
		EmailRaw: "Test@Example.com ", RequestID: uuid.NewString(),
	})
	if err != nil || out.Status != "if_exists_verification_sent" {
		t.Fatalf("err=%v out=%+v", err, out)
	}
	if len(store.records) != 1 {
		t.Fatalf("debe registrar 1 par, got %d", len(store.records))
	}
}

func TestResendGenericoInexistenteYActive(t *testing.T) {
	repo := newMockRepo()
	store := newMockVerifyStore()
	repo.byEmail["active@example.com"] = &user.User{ID: uuid.NewString(), EmailNormalized: "active@example.com", Status: user.StatusActive}
	s := resendSvc(store, repo)
	for _, email := range []string{"nadie@example.com", "active@example.com", "no-es-email"} {
		out, err := s.Execute(context.Background(), ResendInput{EmailRaw: email, RequestID: uuid.NewString()})
		if err != nil || out.Status != "if_exists_verification_sent" {
			t.Fatalf("%s: err=%v out=%+v", email, err, out)
		}
	}
	if len(store.records) != 0 {
		t.Fatal("no debe crear registros en genéricos")
	}
}

func TestResendCooldownSupersede(t *testing.T) {
	repo := newMockRepo()
	store := newMockVerifyStore()
	uid := uuid.NewString()
	seedPending(repo, "test@example.com", uid)
	s := resendSvc(store, repo)
	in := ResendInput{EmailRaw: "test@example.com", RequestID: uuid.NewString()}
	if _, err := s.Execute(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	// Segundo reenvío con cuota bloqueada → 202 genérico sin nuevo registro.
	store.quotaAllow = false
	n := len(store.records)
	in.RequestID = uuid.NewString()
	out, err := s.Execute(context.Background(), in)
	if err != nil || out.Status != "if_exists_verification_sent" {
		t.Fatalf("err=%v out=%+v", err, out)
	}
	if len(store.records) != n {
		t.Fatal("throttled no debe crear registro")
	}
}
