//go:build e2e

// Package e2e agrupa las pruebas de punta a punta del servicio
// (federado, link, MFA, step-up) con Postgres/Redis reales.
//
//	# Unitarios (rápidos, sin infra):
//	go test ./...
//
//	# E2E (requiere docker compose up -d postgres redis):
//	go test -tags e2e ./test/e2e
//
// ATENCIÓN: los E2E borran tablas (users, outbox, email_queue, mfa_*,
// federated_identities, consent_records, verification_tokens) y hacen
// FlushAll en Redis. No los corras contra una base con datos que te importen.
package e2e
