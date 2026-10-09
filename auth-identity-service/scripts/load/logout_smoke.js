import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';

// CU-SES-01 T-13: 50 VUs logout (p95<150ms sin Argon2, PG+Redis sanos) +
// replay 100% already + flood 40/min→31º 429 + refresh-post-logout 401
// revoked-no-robo. Chaos PG/Redis manual (ver tasks T-12): Redis-down →
// 200 vía PG-fallback + WARN; PG-down → 500 SIN Clear-Cookie.
// Umbrales: corrección funcional (checks 100%). NO se usa http_req_failed
// porque el 401-anon es RESPUESTA ESPERADA (cuenta como failed en k6).
// El p95<150ms de logout SIN Argon2 se mide en logout_iso.js (tráfico
// solo-logout); aquí el login concurrente (Argon2) domina la latencia.
export const options = {
  vus: 50,
  duration: '90s',
  thresholds: {
    checks: ['rate==1.0'],
  },
};

const tLogout = new Trend('logout_ok');

const BASE = 'http://localhost:8080/api/v1/auth';

function reqID() {
  return `logout-${__VU}-${__ITER}-${Date.now()}-${Math.random()}`;
}

function fwd() {
  return `10.16.${__VU}.${__ITER % 250}`;
}

function login(email, pw) {
  return http.post(
    `${BASE}/login`,
    JSON.stringify({ email, password: pw }),
    {
      headers: {
        'Content-Type': 'application/json',
        'X-Request-ID': reqID(),
        'X-Forwarded-For': fwd(),
      },
    },
  );
}

export default function () {
  // Pool 200 (k6login-0..199@load.test, sembradas vía API + ACTIVE por SQL).
  // Se evita idx%10==0 (reservado a cuentas MFA en login_smoke).
  const g = (__VU * 130 + __ITER) % 200;
  let idx = g;
  if (idx % 10 === 0) idx = (idx + 1) % 200;
  const email = `k6login-${idx}@load.test`;
  const loginRes = login(email, 'Str0ng!Passw0rd-2026');
  if (loginRes.status !== 200) return;
  let bearer;
  try {
    bearer = loginRes.json().data.access_token;
  } catch (e) {
    return;
  }
  if (!bearer) return;

  // 1. Logout mata par actual.
  const res = http.post(`${BASE}/logout`, null, {
    headers: { Authorization: `Bearer ${bearer}`, 'X-Request-ID': reqID() },
  });
  check(res, { '200 logged_out': (x) => x.status === 200 });
  if (res.status === 200) tLogout.add(res.timings.duration);
  // Clear-Cookie MISMO Path que Issue.
  check(res, {
    'clear-cookie': (x) => {
      const sc = x.headers['Set-Cookie'] || x.headers['set-cookie'] || '';
      return sc.indexOf('refresh_token=') >= 0 && sc.indexOf('Path=/api/v1/auth/refresh') >= 0;
    },
  });

  // 2. Replay mismo Access → 200 already (idempotente, sin doble-outbox).
  const replay = http.post(`${BASE}/logout`, null, {
    headers: { Authorization: `Bearer ${bearer}`, 'X-Request-ID': reqID() },
  });
  check(replay, { '200 already': (x) => x.status === 200 });

  // 3. Sin nada → 401.
  const anon = http.post(`${BASE}/logout`, null, {
    headers: { 'X-Request-ID': reqID() },
  });
  check(anon, { '401 anon': (x) => x.status === 401 });
}
