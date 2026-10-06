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

func TestSetupStale401(t *testing.T) {
	s, _, _, _ := mfaSvc()
	_, err := s.Setup(context.Background(), SetupInput{
		User: AuthUser{ID: "u", AuthTime: time.Now().UTC().Add(-30 * time.Minute)},
		RequestID: uuid.NewString(),
	})
	if !errors.Is(err, user.ErrStepUpRequired) {
		t.Fatalf("stale: %v", err)
	}
}

func TestSetupEnableOKBackupsUnaVez(t *testing.T) {
	s, secrets, _, totp := mfaSvc()
	uid := uuid.NewString()
	repo := s.Users.(*mockRepo)
	seedMFAUser(repo, "mfa@example.com", uid)
	out, err := s.Setup(context.Background(), SetupInput{User: freshAuthUser(uid), RequestID: uuid.NewString()})
	if err != nil || out.SecretB32 == "" || out.ExpiresIn != 600 {
		t.Fatalf("setup: %v %+v", err, out)
	}
	if !strings.Contains(out.OTPAuthURL, "otpauth://totp/") {
		t.Fatalf("otpauth: %s", out.OTPAuthURL)
	}
	// Enable con código del counter actual.
	counter := auth.NewCounter(time.Now().UTC())
	totp.codes[counter] = "654321"
	en, err := s.Enable(context.Background(), EnableInput{
		User: freshAuthUser(uid), Code: "654321", RequestID: uuid.NewString(),
	})
	if err != nil || en.Status != "enabled" || len(en.BackupCodes) != 10 {
		t.Fatalf("enable: %v %+v", err, en)
	}
	if _, ok := secrets.active[uid]; !ok {
		t.Fatal("debe promover a activo")
	}
	// Segundo setup → already enabled.
	if _, err := s.Setup(context.Background(), SetupInput{User: freshAuthUser(uid), RequestID: uuid.NewString()}); !errors.Is(err, auth.ErrAlreadyEnabled) {
		t.Fatalf("already: %v", err)
	}
}

func TestEnableSinStaged400(t *testing.T) {
	s, _, _, _ := mfaSvc()
	uid := uuid.NewString()
	seedMFAUser(s.Users.(*mockRepo), "x@y.co", uid)
	_, err := s.Enable(context.Background(), EnableInput{
		User: freshAuthUser(uid), Code: "123456", RequestID: uuid.NewString(),
	})
	if !errors.Is(err, auth.ErrNoStaged) {
		t.Fatalf("sin staged: %v", err)
	}
}

func TestDisableUltimoFactor400(t *testing.T) {
	s, _, _, _ := mfaSvc()
	uid := uuid.NewString()
	repo := s.Users.(*mockRepo)
	// Solo-MFA sin password: último factor inamovible.
	repo.byEmail["solo@example.com"] = &user.User{ID: uid, EmailNormalized: "solo@example.com", Status: user.StatusActive}
	s.Secrets.(*fakeSecrets).active[uid] = []byte("enc:x")
	_, err := s.Disable(context.Background(), DisableInput{User: freshAuthUser(uid), RequestID: uuid.NewString()})
	if !errors.Is(err, user.ErrLastAuthFactor) {
		t.Fatalf("último: %v", err)
	}
}

func TestDisableConResto200(t *testing.T) {
	s, _, _, _ := mfaSvc()
	uid := uuid.NewString()
	repo := s.Users.(*mockRepo)
	repo.byEmail["c@example.com"] = &user.User{ID: uid, EmailNormalized: "c@example.com", Status: user.StatusActive,
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=4$salt$hash"}
	s.Secrets.(*fakeSecrets).active[uid] = []byte("enc:x")
	out, err := s.Disable(context.Background(), DisableInput{User: freshAuthUser(uid), RequestID: uuid.NewString()})
	if err != nil || out.Status != "disabled" {
		t.Fatalf("disable: %v %+v", err, out)
	}
}
