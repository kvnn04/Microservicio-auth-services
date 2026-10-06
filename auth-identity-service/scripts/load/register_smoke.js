import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';

export const options = {
  vus: 10,
  duration: '30s',
  thresholds: {
    http_req_duration: ['p(95)<900', 'p(99)<1500'],
  },
};

const successTrend = new Trend('reg_success_duration');
const dupTrend = new Trend('reg_dup_duration');

export default function () {
  // 90% únicos, 10% duplicado fijo para medir timing shadow (anti-enumeración).
  const isDup = (__ITER % 10) === 9;
  const email = isDup
    ? 'dup-timing@example.com'
    : `user${__VU}_${__ITER}_${Date.now()}@example.com`;
  const payload = JSON.stringify({
    email: email, password: 'Str0ng!Passw0rd-2026',
    terms_accepted: true, terms_version: 'v2026.10', privacy_version: 'v2026.10',
  });
  // IP única por VU/iter para no disparar rate-limit IP (10/min) durante la medición.
  const fwd = `10.0.${__VU}.${__ITER % 250}`;
  const res = http.post('http://localhost:8080/api/v1/auth/register', payload, {
    headers: {
      'Content-Type': 'application/json',
      'X-Request-ID': `${__VU}-${__ITER}-${Date.now()}`,
      'X-Forwarded-For': fwd,
    },
  });
  check(res, { '201': (r) => r.status === 201 });
  if (res.status === 201) {
    if (isDup) {
      dupTrend.add(res.timings.duration);
    } else {
      successTrend.add(res.timings.duration);
    }
  }
}
