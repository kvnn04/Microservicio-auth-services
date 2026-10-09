//go:build e2e

// Package e2e agrupa las pruebas de punta a punta del servicio
// (federado, link, MFA, step-up) con Postgres/Redis reales.
//
//	# Unitarios (rápidos, sin infra):
//	go test ./...
//
//	# E2E (requiere docker compose up -d postgres redis + credenciales reales):
//	# PowerShell: $env:DATABASE_URL='<tu-DATABASE_URL con 127.0.0.1 en vez de postgres>'
//	go test -tags e2e ./test/e2e
//
// Sin DATABASE_URL se usa el fallback postgres://auth:auth@127.0.0.1:5432,
// que solo vale si el contenedor se inicializó con esa clave.
// Ojo: en Windows, 'localhost' puede resolver a ::1 (wslrelay) y caer en
// otro postgres; por eso el fallback usa 127.0.0.1 explícito.
//
// ATENCIÓN: los E2E borran tablas (users, outbox, email_queue, mfa_*,
// federated_identities, consent_records, verification_tokens) y hacen
// FlushAll en Redis. No los corras contra una base con datos que te importen.
package e2e
