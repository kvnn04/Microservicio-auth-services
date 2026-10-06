import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';
import { SharedArray } from 'k6/data';

const tokens = new SharedArray('verify-tokens', () =>
  JSON.parse(open('./verify_tokens.json')),
);

export const options = {
  vus: 15,
  duration: '45s',
  thresholds: {
    http_req_duration: ['p(95)<300', 'p(99)<600'],
  },
};

const validTrend = new Trend('verify_valid_duration');
const invalidTrend = new Trend('verify_invalid_duration');

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
function randomToken() {
  let s = '';
  for (let i = 0; i < 43; i++) {
    s += B64[Math.floor(Math.random() * 64)];
  }
  return s;
}

export default function () {
  const r = Math.random();
  const fwd = `10.1.${__VU}.${__ITER % 250}`;
  let url;
  let isInvalid = false;
  if (r < 0.7) {
    // Válido único (70%): partición disjunta por VU (15×400=6000 tokens,
    // requiere tokens.length>=6000; sin solape → sin 429 espurios).
    const idx = (__VU * 400 + __ITER) % tokens.length;
    url = `http://localhost:8080/api/v1/auth/verify-email?token=${tokens[idx].t}`;
  } else if (r < 0.9) {
    // Inválido aleatorio con formato válido (20%): camino anti-oráculo.
    url = `http://localhost:8080/api/v1/auth/verify-email?token=${randomToken()}`;
    isInvalid = true;
  } else {
    // Reuso (10%): pool de 500 ya consumidos → already_verified.
    const idx = (__VU * 7 + __ITER) % 500;
    url = `http://localhost:8080/api/v1/auth/verify-email?token=${tokens[idx].t}`;
  }
  const res = http.get(url, {
    headers: {
      'X-Request-ID': `${__VU}-${__ITER}-${Date.now()}`,
      'X-Forwarded-For': fwd,
    },
  });
  if (isInvalid) {
    check(res, { '400': (x) => x.status === 400 });
    if (res.status === 400) invalidTrend.add(res.timings.duration);
  } else {
    check(res, { '200': (x) => x.status === 200 });
    if (res.status === 200) validTrend.add(res.timings.duration);
  }
}
