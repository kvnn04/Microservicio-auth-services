import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';
import { SharedArray } from 'k6/data';
import exec from 'k6/execution';

// CU-SES-02 T-13 (medición aislada): tráfico SOLO-global, sin Argon2.
// Bearers pre-generados (1 sesión viva c/u) en bearers_global.json.
// Un tiro por bearer (sin replay: el bucket 5/hora-user no debe falsear).
// Umbral del plan: p95<300ms con PG+Redis sanos.
// Uso: k6 run --vus 10 --iterations 200 scripts/load/logout_global_iso.js
export const options = {
  thresholds: {
    global_iso: ['p(95)<300'],
    checks: ['rate==1.0'],
  },
};

const tGlobal = new Trend('global_iso');

const BASE = 'http://localhost:8081/api/v1/auth';
const bearers = new SharedArray('bearers', function () {
  return JSON.parse(open('./bearers_global.json'));
});

export default function () {
  // iterationInTest es ÚNICO global ( __ITER es local-por-VU y reutilizaría
  // bearers entre VUs, falseando 429 del bucket 5/hora — lección 2026-10-06).
  const tok = bearers[exec.scenario.iterationInTest % bearers.length];
  const res = http.post(`${BASE}/logout-global`, null, {
    headers: {
      Authorization: `Bearer ${tok}`,
      'X-Request-ID': `giso-${__VU}-${__ITER}-${Date.now()}`,
      'X-Forwarded-For': `10.26.${__VU}.${__ITER % 250}`,
    },
  });
  check(res, { '200 global': (x) => x.status === 200 });
  if (res.status === 200) tGlobal.add(res.timings.duration);
}
