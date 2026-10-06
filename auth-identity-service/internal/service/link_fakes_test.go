package service

import (
	"context"

	"auth-identity-service/internal/domain/user"
)

type fakeLinkStore struct {
	bySub       map[string]*user.User
	byUserProv  map[string]*user.FederatedIdentity
	links       map[string][]user.FederatedIdentity
	hasPassword map[string]bool
	linkErr     error
}

func newFakeLinkStore() *fakeLinkStore {
	return &fakeLinkStore{
		bySub: map[string]*user.User{}, byUserProv: map[string]*user.FederatedIdentity{},
		links: map[string][]user.FederatedIdentity{}, hasPassword: map[string]bool{},
	}
}

func (f *fakeLinkStore) FindByProviderSub(_ context.Context, _ user.Provider, sub string) (*user.FederatedIdentity, *user.User, error) {
	if u, ok := f.bySub[sub]; ok {
		return &user.FederatedIdentity{Provider: user.ProviderGoogle, Sub: sub}, u, nil
	}
	return nil, nil, user.ErrNotFound
}
func (f *fakeLinkStore) FindUserByEmailNormalized(_ context.Context, _ string) (*user.User, error) {
	return nil, user.ErrNotFound
}
func (f *fakeLinkStore) CreateUserWithFederation(_ context.Context, u *user.User, fi *user.FederatedIdentity, _ []user.OutboxPayload, _ user.MailPayload, _ user.RegistrationContext) error {
	return nil
}
func (f *fakeLinkStore) LinkTx(_ context.Context, fi *user.FederatedIdentity, _ []user.OutboxPayload, _ []user.MailPayload) error {
	if f.linkErr != nil {
		return f.linkErr
	}
	if u, ok := f.bySub[fi.Sub]; ok {
		if u.ID == fi.UserID {
			return user.ErrAlreadyLinkedSelf
		}
		return user.ErrCollisionForeign
	}
	key := fi.UserID + ":" + string(fi.Provider)
	if _, ok := f.byUserProv[key]; ok {
		return user.ErrProviderTaken
	}
	f.byUserProv[key] = fi
	f.bySub[fi.Sub] = &user.User{ID: fi.UserID}
	f.links[fi.UserID] = append(f.links[fi.UserID], *fi)
	return nil
}

func (f *fakeLinkStore) UnlinkTx(_ context.Context, userID string, p user.Provider, _ []user.OutboxPayload, _ user.MailPayload) (bool, error) {
	key := userID + ":" + string(p)
	if _, ok := f.byUserProv[key]; !ok {
		return false, nil
	}
	delete(f.byUserProv, key)
	ls := f.links[userID][:0]
	for _, l := range f.links[userID] {
		if l.Provider != p {
			ls = append(ls, l)
		}
	}
	f.links[userID] = ls
	return true, nil
}

func (f *fakeLinkStore) ListByUser(_ context.Context, userID string) ([]user.FederatedIdentity, bool, error) {
	return f.links[userID], f.hasPassword[userID], nil
}
