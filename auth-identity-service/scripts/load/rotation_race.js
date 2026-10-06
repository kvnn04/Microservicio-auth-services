import http from 'k6/http';
import { check } from 'k6';
import { SharedArray } from 'k6/data';
import exec from 'k6/execution';

// CU-SES-04 T-13 (race): 2 VUs martillan los MISMOS 5 bearers con MISMO
// device (misma IP/UA) → solo 200/409 legítimos, NUNCA global ni doble-200
// para la misma generación. Verificación dura post-run por SQL:
// 5 families con counter==1 y 0 reuse_detected de esos usuarios.
// Bearers en bearers_race.json (k6q-*, 5 pares {rt, ip}).
// Uso: k6 run --vus 2 --iterations 20 scripts/load/rotation_race.js
export const options = {
  thresholds: {
    checks: ['rate==1.0'],
  },
};

const BASE = 'http://localhost:8081/api/v1/auth';
const bearers = new SharedArray('bearers', function () {
  return JSON.parse(open('./bearers_race.json'));
});

export default function () {
  const b = bearers[exec.scenario.iterationInTest % bearers.length];
  const res = http.post(`${BASE}/refresh`, JSON.stringify({ refresh_token: b.rt }), {
    headers: {
      'Content-Type': 'application/json',
      'X-Request-ID': `rrace-${exec.scenario.iterationInTest}-${__VU}-${__ITER}`,
      'X-Forwarded-For': b.ip,
      'User-Agent': 'k6-rotation/1.0',
      'X-Client-Type': 'native',
    },
  });
  check(res, {
    '200-o-409': (x) => x.status === 200 || x.status === 409,
    'nunca-compromised': (x) => (x.body || '').indexOf('SESSION_COMPROMISED') < 0,
  });
}
