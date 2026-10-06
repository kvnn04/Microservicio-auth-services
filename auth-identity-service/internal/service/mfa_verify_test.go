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

func verifySetup(s *MFAService, chal *fakeChal, totp *fakeTOTP, uid, cid string, counter int64, code string) {
	chal.live[cid] = uid
	totp.codes[counter] = code
	s.PreToken = &fakePreToken{claims: auth.PreTokenClaims{Sub: uid, ChallengeID: cid, ExpiresAt: time.Now().Add(5 * time.Minute).Unix()}}
}

func TestVerifyOKQuema(t *testing.T) {
	s, _, chal, totp := mfaSvc()
	uid := uuid.NewString()
	_ = user.StatusActive
	s.Secrets.(*fakeSecrets).active[uid] = []byte("enc:12345678901234567890")
	counter := auth.NewCounter(time.Now().UTC())
	verifySetup(s, chal, totp, uid, "ch-1", counter, "424242")
	in := VerifyInput{MFAToken: "tok", Code: "424242", RequestID: uuid.NewString()}
	out, err := s.Verify(context.Background(), in)
	if err != nil || out.Status != "active" || out.Session == nil {
		t.Fatalf("err=%v out=%+v", err, out)
	}
	// Replay mismo body → 401 (challenge consumido).
	if _, err := s.Verify(context.Background(), in); !errors.Is(err, auth.ErrInvalidMFA) {
		t.Fatalf("replay challenge debe ser 401, got %v", err)
	}
}

func TestVerifyReplayMismoCounter401(t *testing.T) {
	s, _, chal, totp := mfaSvc()
	uid := uuid.NewString()
	s.Secrets.(*fakeSecrets).active[uid] = []byte("enc:12345678901234567890")
	counter := auth.NewCounter(time.Now().UTC())
	// Primer challenge OK.
	verifySetup(s, chal, totp, uid, "ch-a", counter, "111111")
	in := VerifyInput{MFAToken: "tok", Code: "111111", RequestID: uuid.NewString()}
	if _, err := s.Verify(context.Background(), in); err != nil {
		t.Fatalf("1º: %v", err)
	}
	// Segundo challenge fresco, MISMO código/counter → replay 401 aunque cripto OK.
	verifySetup(s, chal, totp, uid, "ch-b", counter, "111111")
	in2 := VerifyInput{MFAToken: "tok2", Code: "111111", RequestID: uuid.NewString()}
	if _, err := s.Verify(context.Background(), in2); !errors.Is(err, auth.ErrInvalidMFA) {
		t.Fatalf("replay counter debe ser 401, got %v", err)
	}
}

func TestVerifyQuintoFalloQuema(t *testing.T) {
	s, _, chal, totp := mfaSvc()
	uid := uuid.NewString()
	s.Secrets.(*fakeSecrets).active[uid] = []byte("enc:12345678901234567890")
	counter := auth.NewCounter(time.Now().UTC())
	totp.codes[counter] = "999999"
	s.PreToken = &fakePreToken{claims: auth.PreTokenClaims{Sub: uid, ChallengeID: "ch-x", ExpiresAt: time.Now().Add(5 * time.Minute).Unix()}}
	chal.live["ch-x"] = uid
	for i := 0; i < 5; i++ {
		in := VerifyInput{MFAToken: "tok", Code: "000000", RequestID: uuid.NewString()}
		if _, err := s.Verify(context.Background(), in); !errors.Is(err, auth.ErrInvalidMFA) {
			t.Fatalf("fallo %d: %v", i, err)
		}
		if i < 4 {
			// Re-registra challenge (Consume lo borra solo en... no: fallos no consumen).
			chal.live["ch-x"] = uid
		}
	}
	// 6º intento: challenge quemado → 401 igual.
	in := VerifyInput{MFAToken: "tok", Code: "999999", RequestID: uuid.NewString()}
	if _, err := s.Verify(context.Background(), in); !errors.Is(err, auth.ErrInvalidMFA) {
		t.Fatalf("quemado: %v", err)
	}
}

func TestVerifyExpiradoIgual(t *testing.T) {
	s, _, _, _ := mfaSvc()
	s.PreToken = &fakePreToken{err: errors.New("expired")}
	in := VerifyInput{MFAToken: "bad", Code: "123456", RequestID: uuid.NewString()}
	_, err := s.Verify(context.Background(), in)
	if !errors.Is(err, auth.ErrInvalidMFA) {
		t.Fatalf("expirado debe ser opaco 401: %v", err)
	}
	// Challenge inexistente también opaco.
	s.PreToken = &fakePreToken{claims: auth.PreTokenClaims{Sub: "u", ChallengeID: "nope"}}
	if _, err := s.Verify(context.Background(), in); !errors.Is(err, auth.ErrInvalidMFA) {
		t.Fatalf("miss debe ser opaco: %v", err)
	}
}
