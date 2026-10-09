import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';

// CU-AUTH-01 T-13 (alcance documentado): 15 VUs 60s vs 150/4min del plan
// (laptop; Argon2 concurrente saturaría). Timing bloqueante |p50|<80ms.
export const options = {
  vus: 15,
  duration: '60s',
  thresholds: {
    http_req_duration: ['p(95)<900'],
  },
};

const tGood = new Trend('login_good');
const tBad = new Trend('login_bad');
const tNoExist = new Trend('login_noexist');
const tPending = new Trend('login_pending');

function post(email, pw, fwd) {
  return http.post(
    'http://localhost:8080/api/v1/auth/login',
    JSON.stringify({ email: email, password: pw }),
    {
      headers: {
        'Content-Type': 'application/json',
        'X-Request-ID': `login-${__VU}-${__ITER}-${Date.now()}-${Math.random()}`,
        'X-Forwarded-For': fwd,
      },
    },
  );
}

export default function () {
  const fwd = `10.8.${__VU}.${__ITER % 250}`;
  const r = Math.random();
  // Particiones disjuntas por VU (sin solapar buckets login:account 5/min).
  const g = (__VU * 130 + __ITER) % 2000; // buena/mala: 130 slots por VU
  const m = (__VU * 14 + __ITER) % 200; // MFA: 200 cuentas
  const p = (__VU * 7 + __ITER) % 100; // pending
  let res;
  if (r < 0.6) {
    // Buena sin MFA (g%10==0 son MFA → +1).
    let idx = g;
    if (idx % 10 === 0) idx = (idx + 1) % 2000;
    res = post(`k6login-${idx}@load.test`, 'Str0ng!Passw0rd-2026', fwd);
    check(res, { '200': (x) => x.status === 200 });
    if (res.status === 200) tGood.add(res.timings.duration);
  } else if (r < 0.7) {
    // MFA (i%10==0).
    const idx = m * 10;
    res = post(`k6login-${idx}@load.test`, 'Str0ng!Passw0rd-2026', fwd);
    check(res, { '202': (x) => x.status === 202 });
  } else if (r < 0.8) {
    // Mala password sobre la misma cuenta buena (fails bajos por reset).
    let idx = g;
    if (idx % 10 === 0) idx = (idx + 1) % 2000;
    res = post(`k6login-${idx}@load.test`, 'Wrong!Pass-2026', fwd);
    check(res, { '401': (x) => x.status === 401 });
    if (res.status === 401) tBad.add(res.timings.duration);
  } else if (r < 0.9) {
    // Inexistente.
    res = post(`noexiste-${__VU}-${__ITER}-${Date.now()}@load.test`, 'Str0ng!Passw0rd-2026', fwd);
    check(res, { '401': (x) => x.status === 401 });
    if (res.status === 401) tNoExist.add(res.timings.duration);
  } else {
    // Pending con buena.
    res = post(`k6pend-${p}@load.test`, 'Str0ng!Passw0rd-2026', fwd);
    check(res, { '401': (x) => x.status === 401 });
    if (res.status === 401) tPending.add(res.timings.duration);
  }
}
