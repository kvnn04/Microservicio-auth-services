import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';

// CU-REG-05 T-13: GET cacheado + POST versión vieja (100% 400, 0 inserts).
export const options = {
  scenarios: {
    get_active: {
      executor: 'constant-vus',
      vus: 50,
      duration: '30s',
      exec: 'getActive',
    },
    post_old: {
      executor: 'constant-vus',
      vus: 5,
      duration: '30s',
      exec: 'postOld',
    },
  },
  thresholds: {
    http_req_duration: ['p(95)<150'],
  },
};

const getTrend = new Trend('legal_get_duration');
const oldTrend = new Trend('legal_old_duration');

export function getActive() {
  const res = http.get('http://localhost:8080/api/v1/legal/active', {
    headers: { 'X-Forwarded-For': `10.4.${__VU}.${__ITER % 250}` },
  });
  check(res, { '200': (r) => r.status === 200 });
  if (res.status === 200) getTrend.add(res.timings.duration);
}

export function postOld() {
  const payload = JSON.stringify({
    email: `old-${__VU}-${__ITER}-${Date.now()}@load.test`,
    password: 'Str0ng!Passw0rd-2026',
    terms_accepted: true,
    terms_version: 'v2026.09',
    privacy_version: 'v2026.10',
  });
  const res = http.post('http://localhost:8080/api/v1/auth/register', payload, {
    headers: {
      'Content-Type': 'application/json',
      'X-Request-ID': `old-${__VU}-${__ITER}-${Date.now()}`,
      'X-Forwarded-For': `10.5.${__VU}.${__ITER % 250}`,
    },
  });
  check(res, { '400 outdated': (r) => r.status === 400 });
  if (res.status === 400) oldTrend.add(res.timings.duration);
}
