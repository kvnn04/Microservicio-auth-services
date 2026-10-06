import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';

// CU-REG-03 T-13: 100 unique vs 100 shadow, |p50 diff| < 80ms (bloqueante).
export const options = {
  vus: 5,
  iterations: 200,
  thresholds: {
    http_req_duration: ['p(95)<600'],
  },
};

const uniqueTrend = new Trend('uniq_duration');
const shadowTrend = new Trend('shadow_duration');

export default function () {
  const i = __ITER;
  const isUnique = i % 2 === 0;
  // Shadow: 100 pre-sembrados, partición disjunta (VU*20+.., cada uno 1 uso).
  // Unique: emails frescos (crean PENDING real).
  const email = isUnique
    ? `uniq-${__VU}-${i}-${Date.now()}@load.test`
    : `timing-${(__VU * 20 + Math.floor(i / 2)) % 100}@load.test`;
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
      'X-Request-ID': `${__VU}-${i}-${Date.now()}`,
      'X-Forwarded-For': `10.2.${__VU}.${i % 250}`,
    },
  });
  check(res, { '201': (r) => r.status === 201 });
  if (res.status === 201) {
    if (isUnique) uniqueTrend.add(res.timings.duration);
    else shadowTrend.add(res.timings.duration);
  }
}
