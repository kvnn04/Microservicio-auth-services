import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';
import { SharedArray } from 'k6/data';
import exec from 'k6/execution';

// CU-SES-04 T-13 (serie): 1 rotate por bearer pre-generado (sin logins en
// caliente, sin Argon2). Mide p95<250ms del plan.
// Bearers en bearers_rot.json (k6r-*, 1 uso c/u vía iterationInTest global).
// Uso: k6 run --vus 10 --iterations 200 scripts/load/rotation_iso.js
export const options = {
  thresholds: {
    rotation_iso: ['p(95)<250'],
    checks: ['rate==1.0'],
  },
};

const tRot = new Trend('rotation_iso');

const BASE = 'http://localhost:8081/api/v1/auth';
const bearers = new SharedArray('bearers', function () {
  return JSON.parse(open('./bearers_rot.json'));
});

export default function () {
  const b = bearers[exec.scenario.iterationInTest % bearers.length];
  const res = http.post(`${BASE}/refresh`, JSON.stringify({ refresh_token: b.rt }), {
    headers: {
      'Content-Type': 'application/json',
      'X-Request-ID': `riso-${exec.scenario.iterationInTest}`,
      'X-Forwarded-For': b.ip,
      'User-Agent': 'k6-rotation/1.0',
      'X-Client-Type': 'native',
    },
  });
  check(res, { '200 rotated': (x) => x.status === 200 });
  if (res.status === 200) tRot.add(res.timings.duration);
}
