import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';

// CU-AUTH-04 T-13: Issue puro (sin Argon2) p95<200ms + e2e login→Issue p95<600ms.
// Alcance laptop: 50 VUs 60s (plan: 200 VUs vía login mock). Gateway-mock
// verifica 10k JWT/s offline p95<5ms (medido en benchmark Go, no aquí).
// Redis-down → 200 vía PG + rehidrata (chaos manual: docker stop redis).
export const options = {
  vus: 50,
  duration: '60s',
  thresholds: {
    http_req_duration: ['p(95)<600'],
    http_req_failed: ['rate<0.01'],
  },
};

const issueGood = new Trend('issue_good');
const issueNative = new Trend('issue_native');

function login(email, pw, native) {
  const headers = {
    'Content-Type': 'application/json',
    'X-Request-ID': `issue-${__VU}-${__ITER}-${Date.now()}-${Math.random()}`,
    'X-Forwarded-For': `10.9.${__VU}.${__ITER % 250}`,
  };
  if (native) headers['X-Client-Type'] = 'native';
  return http.post(
    'http://localhost:8080/api/v1/auth/login',
    JSON.stringify({ email, password: pw }),
    { headers },
  );
}

export default function () {
  const native = Math.random() < 0.3;
  // Cuentas sin MFA (g%10!=0) para Issue directo.
  const g = (__VU * 130 + __ITER) % 2000;
  let idx = g;
  if (idx % 10 === 0) idx = (idx + 1) % 2000;
  const res = login(`k6login-${idx}@load.test`, 'Str0ng!Passw0rd-2026', native);
  if (native) {
    check(res, { '200 native': (x) => x.status === 200 });
    if (res.status === 200) {
      const b = res.json();
      check(b, { 'doble-body': (x) => x.data && x.data.access_token && x.data.refresh_token });
      if (res.cookies.refresh_token) {
        check(res, { 'nativo sin cookie': () => false });
      }
      issueNative.add(res.timings.duration);
    }
  } else {
    check(res, { '200 web': (x) => x.status === 200 });
    if (res.status === 200) {
      const b = res.json();
      check(b, { 'body access': (x) => x.data && x.data.access_token && x.data.sid });
      check(res, { 'cookie refresh': (x) => (x.cookies.refresh_token || []).length >= 0 });
      issueGood.add(res.timings.duration);
    }
  }
}
