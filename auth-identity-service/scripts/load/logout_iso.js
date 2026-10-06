import http from 'k6/http';
import { check } from 'k6';
import { Trend, Counter } from 'k6/metrics';
import { SharedArray } from 'k6/data';
import exec from 'k6/execution';

// CU-SES-01 T-13 (medición aislada): tráfico SOLO-logout, sin Argon2.
// Los bearers se pre-generan (login secuencial fuera de k6) en
// bearers.json: ["jwt-0", ..., "jwt-N"]. Cada iteración consume uno:
// logout (200 logged_out) + replay mismo Bearer (200 already).
// Umbral del plan: p95<150ms sin Argon2, PG+Redis sanos.
// Uso: k6 run --vus 10 --iterations 200 scripts/load/logout_iso.js
export const options = {
  thresholds: {
    logout_ok: ['p(95)<150'],
    checks: ['rate==1.0'],
  },
};

const tLogout = new Trend('logout_ok');
const tReplay = new Trend('logout_replay');
const cFirst = new Counter('logout_first_total');

const BASE = 'http://localhost:8081/api/v1/auth';
const bearers = new SharedArray('bearers', function () {
  return JSON.parse(open('./bearers.json'));
});

export default function () {
  // iterationInTest global-único ( __ITER es local-por-VU; con endpoints
  // idempotentes no falsea, pero se deja robusto igual).
  const tok = bearers[exec.scenario.iterationInTest % bearers.length];
  const res = http.post(`${BASE}/logout`, null, {
    headers: {
      Authorization: `Bearer ${tok}`,
      'X-Request-ID': `iso-${__VU}-${__ITER}-${Date.now()}`,
      'X-Forwarded-For': `10.17.${__VU}.${__ITER % 250}`,
    },
  });
  check(res, { '200 logged_out': (x) => x.status === 200 });
  if (res.status === 200) {
    tLogout.add(res.timings.duration);
    cFirst.add(1);
  }
  const replay = http.post(`${BASE}/logout`, null, {
    headers: {
      Authorization: `Bearer ${tok}`,
      'X-Request-ID': `iso-replay-${__VU}-${__ITER}-${Date.now()}`,
      'X-Forwarded-For': `10.17.${__VU}.${__ITER % 250}`,
    },
  });
  check(replay, { '200 already': (x) => x.status === 200 });
  if (replay.status === 200) tReplay.add(replay.timings.duration);
}
