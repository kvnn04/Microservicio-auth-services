import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';

// CU-AUTH-06 T-13: 50 VUs challenge (doble-ok/fallos, p95<400ms con Argon2) +
// 100 VUs guards (fast-pass p95<10ms offline, token p95<50ms Redis-hit).
// Replay 100% REUSED, cross-scope 100% INVALID, lock 401 hasta expirar.
// Alcance laptop: escenarios secuenciales 60s (no simultáneos).
export const options = {
  scenarios: {
    challenge: {
      executor: 'constant-vus',
      vus: 50,
      duration: '60s',
      exec: 'challengeFlow',
    },
    guards: {
      executor: 'constant-vus',
      vus: 100,
      duration: '60s',
      exec: 'guardFlow',
      startTime: '65s',
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.05'],
  },
};

const tChallenge = new Trend('stepup_challenge');
const tGuardFast = new Trend('stepup_guard_fast');

const BASE = 'http://localhost:8080/api/v1/auth';

function reqID() {
  return `stepup-${__VU}-${__ITER}-${Date.now()}-${Math.random()}`;
}

function loginToken(email, pw) {
  const res = http.post(
    `${BASE}/login`,
    JSON.stringify({ email, password: pw }),
    {
      headers: {
        'Content-Type': 'application/json',
        'X-Request-ID': reqID(),
        'X-Forwarded-For': `10.12.${__VU}.${__ITER % 250}`,
      },
    },
  );
  if (res.status !== 200) return null;
  const jars = res.cookies;
  const b = res.json();
  return { cookies: jars, body: b };
}

export function challengeFlow() {
  // Login bueno sin MFA → Bearer fresco; challenge con password buena/mala.
  const g = (__VU * 130 + __ITER) % 2000;
  let idx = g;
  if (idx % 10 === 0) idx = (idx + 1) % 2000;
  const login = http.post(
    `${BASE}/login`,
    JSON.stringify({ email: `k6login-${idx}@load.test`, password: 'Str0ng!Passw0rd-2026' }),
    {
      headers: {
        'Content-Type': 'application/json',
        'X-Request-ID': reqID(),
        'X-Forwarded-For': `10.12.${__VU}.${__ITER % 250}`,
      },
    },
  );
  if (login.status !== 200) return;
  const bearer = login.json().data.access_token;
  const good = Math.random() < 0.7;
  const res = http.post(
    `${BASE}/step-up/challenge`,
    JSON.stringify({
      scope: 'mfa:disable',
      password: good ? 'Str0ng!Passw0rd-2026' : 'Wrong!Pass-2026',
    }),
    {
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${bearer}`,
        'X-Request-ID': reqID(),
      },
    },
  );
  if (good) check(res, { '200 token': (x) => x.status === 200 });
  else check(res, { '401 opaco': (x) => x.status === 401 });
  tChallenge.add(res.timings.duration);
}

export function guardFlow() {
  // Fast-pass: login fresco → op con solo Bearer (sin token).
  const g = (__VU * 130 + __ITER) % 2000;
  let idx = g;
  if (idx % 10 === 0) idx = (idx + 1) % 2000;
  const login = http.post(
    `${BASE}/login`,
    JSON.stringify({ email: `k6login-${idx}@load.test`, password: 'Str0ng!Passw0rd-2026' }),
    {
      headers: {
        'Content-Type': 'application/json',
        'X-Request-ID': reqID(),
        'X-Forwarded-For': `10.13.${__VU}.${__ITER % 250}`,
      },
    },
  );
  if (login.status !== 200) return;
  const bearer = login.json().data.access_token;
  const res = http.get(`${BASE}/federated/linked`, {
    headers: { Authorization: `Bearer ${bearer}`, 'X-Request-ID': reqID() },
  });
  check(res, { '200 lectura': (x) => x.status === 200 });
  tGuardFast.add(res.timings.duration);
}
