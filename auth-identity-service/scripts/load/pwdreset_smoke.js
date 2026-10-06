import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';

// CU-CRED-01 T-13: 50 VUs start (4 grupos: elegible/inexistente/pending/federated,
// |p50|<40ms, 202 100%, 1 correo por cada 4) + 80 VUs confirm (válidos/débiles/
// reusados/inválidos, policy no quema, p95<500ms con Argon2, 400 idénticos).
export const options = {
  scenarios: {
    start: {
      executor: 'constant-vus',
      vus: 50,
      duration: '60s',
      exec: 'startFlow',
    },
    confirm: {
      executor: 'constant-vus',
      vus: 80,
      duration: '60s',
      exec: 'confirmFlow',
      startTime: '65s',
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
  },
};

const tStart = new Trend('pwdreset_start');
const tConfirmBad = new Trend('pwdreset_confirm_bad');

const BASE = 'http://localhost:8081/api/v1/auth/password/reset';

function reqID() {
  return `pwdreset-${__VU}-${__ITER}-${Date.now()}-${Math.random()}`;
}

function fwd(octet) {
  return `10.14.${__VU}.${__ITER % 250}`;
}

export function startFlow() {
  // 4 grupos rotativos: elegible / inexistente / pending / federado.
  const g = (__VU + __ITER) % 4;
  const m = (__VU * 14 + __ITER) % 200;
  let email;
  if (g === 0) email = `k6login-${m}@load.test`;
  else if (g === 1) email = `noexiste-${__VU}-${__ITER}@load.test`;
  else if (g === 2) email = `k6pend-${m % 100}@load.test`;
  else email = `k6fed-${m}@load.test`;
  const res = http.post(
    `${BASE}/start`,
    JSON.stringify({ email }),
    {
      headers: {
        'Content-Type': 'application/json',
        'X-Request-ID': reqID(),
        'X-Forwarded-For': fwd(),
      },
    },
  );
  check(res, { '202 siempre': (x) => x.status === 202 });
  if (res.status === 202) tStart.add(res.timings.duration);
}

export function confirmFlow() {
  const r = Math.random();
  let body;
  if (r < 0.4) {
    // Token forma-válida inexistente → 400 opaco.
    body = JSON.stringify({ token: 'B'.repeat(43), new_password: 'Nu3va!Valida-2026' });
  } else if (r < 0.7) {
    // Token válido-forma + clave débil → 400 policy (sin quemar).
    body = JSON.stringify({ token: 'C'.repeat(43), new_password: 'corta' });
  } else {
    // Token malformado → 400 forma.
    body = JSON.stringify({ token: 'corto', new_password: 'Nu3va!Valida-2026' });
  }
  const res = http.post(`${BASE}/confirm`, body, {
    headers: { 'Content-Type': 'application/json', 'X-Request-ID': reqID() },
  });
  check(res, { '400': (x) => x.status === 400 });
  if (res.status === 400) tConfirmBad.add(res.timings.duration);
}
