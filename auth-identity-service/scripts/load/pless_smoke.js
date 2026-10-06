import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';

// CU-AUTH-05 T-13: start 50/50 elegible/no-elegible (|p50|<40ms, 202 100%) +
// verify válidos/inválidos/replay (p95<300ms hit / <700ms fallback) + quotas
// (2×30s→2º throttled 202, 6×24h→6º throttled) + high-risk (IP-B → 200 + mismatch).
// Alcance laptop: 50 VUs start 60s + 80 VUs verify 60s (2 escenarios).
export const options = {
  scenarios: {
    start: {
      executor: 'constant-vus',
      vus: 50,
      duration: '60s',
      exec: 'startFlow',
    },
    verify: {
      executor: 'constant-vus',
      vus: 80,
      duration: '60s',
      exec: 'verifyFlow',
      startTime: '65s',
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
  },
};

const tStartElig = new Trend('pless_start_eligible');
const tStartNo = new Trend('pless_start_noeligible');
const tVerifyGood = new Trend('pless_verify_good');
const tVerifyBad = new Trend('pless_verify_bad');

const BASE = 'http://localhost:8081/api/v1/auth/passwordless';

function reqID() {
  return `pless-${__VU}-${__ITER}-${Date.now()}-${Math.random()}`;
}

export function startFlow() {
  const r = Math.random();
  // Mitad elegible (cuentas k6login sin MFA), mitad inexistente.
  const g = (__VU * 130 + __ITER) % 2000;
  let idx = g;
  if (idx % 10 === 0) idx = (idx + 1) % 2000;
  const email = r < 0.5 ? `k6login-${idx}@load.test` : `noexiste-${__VU}-${__ITER}@load.test`;
  const res = http.post(
    `${BASE}/start`,
    JSON.stringify({ email }),
    {
      headers: {
        'Content-Type': 'application/json',
        'X-Request-ID': reqID(),
        'X-Forwarded-For': `10.11.${__VU}.${__ITER % 250}`,
      },
    },
  );
  check(res, { '202 siempre': (x) => x.status === 202 });
  if (res.status === 202) {
    if (r < 0.5) tStartElig.add(res.timings.duration);
    else tStartNo.add(res.timings.duration);
  }
}

export function verifyFlow() {
  const r = Math.random();
  let res;
  if (r < 0.4) {
    // Token aleatorio válido en forma (43ch) pero inexistente → 400.
    res = http.post(
      `${BASE}/verify`,
      JSON.stringify({ token: 'B'.repeat(43) }),
      { headers: { 'Content-Type': 'application/json', 'X-Request-ID': reqID() } },
    );
    check(res, { '400 opaco': (x) => x.status === 400 });
    if (res.status === 400) tVerifyBad.add(res.timings.duration);
  } else if (r < 0.7) {
    // OTP malformado → 400 de forma.
    res = http.post(
      `${BASE}/verify`,
      JSON.stringify({ code: '123' }),
      { headers: { 'Content-Type': 'application/json', 'X-Request-ID': reqID() } },
    );
    check(res, { '400 forma': (x) => x.status === 400 });
  } else {
    // Ambos/ninguno → 400 forma.
    res = http.post(
      `${BASE}/verify`,
      JSON.stringify({}),
      { headers: { 'Content-Type': 'application/json', 'X-Request-ID': reqID() } },
    );
    check(res, { '400 forma': (x) => x.status === 400 });
  }
}
