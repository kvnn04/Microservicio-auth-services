import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';
import { SharedArray } from 'k6/data';

// CU-REG-04 T-13: callback completo (JWKS cache + RSA + Tx) vs fake-IdP local.
const pairs = new SharedArray('fed-pairs', () =>
  JSON.parse(open('./federated_pairs.json')),
);

export const options = {
  vus: 20,
  duration: '60s',
  thresholds: {
    http_req_duration: ['p(95)<400', 'p(99)<800'],
  },
};

const cbTrend = new Trend('fed_callback_duration');

export default function () {
  // Índice único global aproximado (20 VUs × ~15/s × 60s ≈ 18000 < 20000).
  const idx = (__VU * 1000 + __ITER) % pairs.length;
  const p = pairs[idx];
  const res = http.get(
    `http://localhost:8080/api/v1/auth/federated/google/callback?code=${p.code}&state=${p.state}`,
    {
      headers: {
        'X-Request-ID': `${__VU}-${__ITER}-${Date.now()}`,
        'X-Forwarded-For': `10.3.${__VU}.${__ITER % 250}`,
      },
    },
  );
  check(res, { '200': (r) => r.status === 200 });
  if (res.status === 200) cbTrend.add(res.timings.duration);
}
