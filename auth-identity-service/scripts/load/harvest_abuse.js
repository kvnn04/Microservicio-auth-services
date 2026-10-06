import http from 'k6/http';
import { check } from 'k6';

// CU-REG-03 T-13: barrido automatizado frenado.
// 60 emails distintos desde 1 IP fija → 429 desde el 11º; tras 50×429 → bloqueo.
export const options = {
  vus: 1,
  iterations: 62,
  thresholds: {
    http_req_failed: ['rate>0.5'],
  },
};

let saw429 = 0;
let sawBlocked = false;

export default function () {
  const email = `harv-${__ITER}-${Date.now()}@load.test`;
  const payload = JSON.stringify({
    email: email,
    password: 'Str0ng!Passw0rd-2026',
    terms_accepted: true,
    terms_version: 'v2026.10',
    privacy_version: 'v2026.10',
  });
  const res = http.post('http://localhost:8080/api/v1/auth/register', payload, {
    headers: {
      'Content-Type': 'application/json',
      'X-Request-ID': `harv-${__ITER}-${Date.now()}`,
      'X-Forwarded-For': '9.9.9.200',
    },
  });
  if (__ITER < 10) {
    check(res, { '201 primero': (r) => r.status === 201 });
  } else {
    if (res.status === 429) saw429++;
    check(res, { '429 frenado': (r) => r.status === 429 });
    const ra = res.headers['Retry-After'];
    if (__ITER >= 60 && parseInt(ra || '0', 10) > 60) sawBlocked = true;
  }
}

export function handleSummary(data) {
  return {
    stdout: JSON.stringify({
      saw429_hint: 'ver logs checks 429',
      blocked_probe: sawBlocked,
      failed_rate: data.metrics.http_req_failed.values.rate,
    }),
  };
}
