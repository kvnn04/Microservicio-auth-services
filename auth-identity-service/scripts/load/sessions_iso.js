import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';
import { SharedArray } from 'k6/data';
import exec from 'k6/execution';

// CU-SES-03 T-13 (medición aislada): sin logins (sin Argon2).
// Pares pre-generados en pairs.json: [{token, sidA, sidB}] con 2 sesiones
// vivas c/u. Por iteración: lista + revoca-B + repeat-404 + actual-400.
// Umbrales del plan: list p95<120ms PG, revoke p95<200ms.
// Uso: k6 run --vus 8 --iterations 100 scripts/load/sessions_iso.js
export const options = {
  thresholds: {
    sessions_list_iso: ['p(95)<120'],
    sessions_revoke_iso: ['p(95)<200'],
    checks: ['rate==1.0'],
  },
};

const tList = new Trend('sessions_list_iso');
const tRevoke = new Trend('sessions_revoke_iso');

const BASE = 'http://localhost:8080/api/v1/auth';
const pairs = new SharedArray('pairs', function () {
  return JSON.parse(open('./pairs.json'));
});

export default function () {
  const p = pairs[exec.scenario.iterationInTest % pairs.length];
  const fwd = `10.28.${exec.scenario.iterationInTest % 250}.${exec.scenario.iterationInTest % 250}`;

  const list = http.get(`${BASE}/sessions`, {
    headers: { Authorization: `Bearer ${p.token}`, 'X-Request-ID': `siso-l-${exec.scenario.iterationInTest}`, 'X-Forwarded-For': fwd },
  });
  check(list, { '200 list': (x) => x.status === 200 });
  if (list.status === 200) tList.add(list.timings.duration);

  const del = http.del(`${BASE}/sessions/${p.sidB}`, null, {
    headers: { Authorization: `Bearer ${p.token}`, 'X-Request-ID': `siso-d-${exec.scenario.iterationInTest}`, 'X-Forwarded-For': fwd },
  });
  check(del, { '200 revoked': (x) => x.status === 200 });
  if (del.status === 200) tRevoke.add(del.timings.duration);

  const rep = http.del(`${BASE}/sessions/${p.sidB}`, null, {
    headers: { Authorization: `Bearer ${p.token}`, 'X-Request-ID': `siso-r-${exec.scenario.iterationInTest}`, 'X-Forwarded-For': fwd },
  });
  check(rep, { '404 repeat': (x) => x.status === 404 });

  const self = http.del(`${BASE}/sessions/${p.sidA}`, null, {
    headers: { Authorization: `Bearer ${p.token}`, 'X-Request-ID': `siso-s-${exec.scenario.iterationInTest}`, 'X-Forwarded-For': fwd },
  });
  check(self, { '400 actual': (x) => x.status === 400 });
}
