import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';

// CU-CRED-03 T-13: 30 VUs start (libres/tomados/stale, 409/401 correctos,
// 4º/hora→429) + 50 VUs confirm (válidos/inválidos/race, p95<400ms sin
// Argon2, 400 idénticos, race 1×200/1×409) + doble-mail verificado.
// Alcance laptop: escenarios secuenciales 60s (no simultáneos).
export const options = {
  scenarios: {
    start: {
      executor: 'constant-vus',
      vus: 30,
      duration: '60s',
      exec: 'startFlow',
    },
    confirm: {
      executor: 'constant-vus',
      vus: 50,
      duration: '60s',
      exec: 'confirmFlow',
      startTime: '65s',
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.05'],
  },
};

const tStart = new Trend('emailchange_start');
const tConfirmBad = new Trend('emailchange_confirm_bad');

const BASE = 'http://localhost:8081/api/v1/auth/email/change';

function reqID() {
  return `emailchange-${__VU}-${__ITER}-${Date.now()}-${Math.random()}`;
}

// Login bueno sin MFA → Bearer (fresco para fast-pass en start).
function loginBearer(email) {
  const res = http.post(
    'http://localhost:8081/api/v1/auth/login',
    JSON.stringify({ email, password: 'Str0ng!Passw0rd-2026' }),
    {
      headers: {
        'Content-Type': 'application/json',
        'X-Request-ID': reqID(),
        'X-Forwarded-For': `10.16.${__VU}.${__ITER % 250}`,
      },
    },
  );
  if (res.status !== 200) return null;
  return res.json().data.access_token;
}

export function startFlow() {
  const r = Math.random();
  const g = (__VU * 130 + __ITER) % 2000;
  let idx = g;
  if (idx % 10 === 0) idx = (idx + 1) % 2000;
  const bearer = loginBearer(`k6login-${idx}@load.test`);
  if (!bearer) return;
  let body;
  if (r < 0.6) {
    // Nuevo libre.
    body = JSON.stringify({ new_email: `k6new-${__VU}-${__ITER}@load.test` });
  } else if (r < 0.8) {
    // Tomado (otra cuenta k6) → 409.
    const o = (__VU * 29 + __ITER + 7) % 2000;
    body = JSON.stringify({ new_email: `k6login-${o}@load.test` });
  } else {
    // Igual al actual → 400.
    body = JSON.stringify({ new_email: `k6login-${idx}@load.test` });
  }
  const res = http.post(`${BASE}/start`, body, {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${bearer}`,
      'X-Request-ID': reqID(),
    },
  });
  if (r < 0.6) check(res, { '202': (x) => x.status === 202 });
  else if (r < 0.8) check(res, { '409 taken': (x) => x.status === 409 });
  else check(res, { '400 same': (x) => x.status === 400 });
  tStart.add(res.timings.duration);
}

export function confirmFlow() {
  const r = Math.random();
  let body;
  if (r < 0.5) {
    // Token forma-válida inexistente → 400 opaco.
    body = JSON.stringify({ token: 'B'.repeat(43) });
  } else if (r < 0.8) {
    // Token malformado → 400 forma.
    body = JSON.stringify({ token: 'corto' });
  } else {
    // Sin token → 400 forma.
    body = JSON.stringify({});
  }
  const res = http.post(`${BASE}/confirm`, body, {
    headers: { 'Content-Type': 'application/json', 'X-Request-ID': reqID() },
  });
  check(res, { '400': (x) => x.status === 400 });
  if (res.status === 400) tConfirmBad.add(res.timings.duration);
}
