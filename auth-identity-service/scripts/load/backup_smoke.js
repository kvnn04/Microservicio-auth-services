import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';
import { SharedArray } from 'k6/data';

// CU-AUTH-03 T-13: verify-backup (válidos 1 uso, reusos, TOTP-malos).
// Usuarios/códigos pre-sembrados (2500). Login real → 202 → verify.
const codes = new SharedArray('bk-codes', () =>
  JSON.parse(open('./backup_codes.json')),
);

export const options = {
  vus: 15,
  duration: '45s',
  thresholds: {
    http_req_duration: ['p(95)<3000'],
  },
};

const validTrend = new Trend('bk_valid_duration');
const invalidTrend = new Trend('bk_invalid_duration');

function login(email) {
  return http.post(
    'http://localhost:8082/api/v1/auth/login',
    JSON.stringify({ email: email, password: 'Str0ng!Passw0rd-2026' }),
    {
      headers: {
        'Content-Type': 'application/json',
        'X-Request-ID': `bk-${__VU}-${__ITER}-${Date.now()}`,
        'X-Forwarded-For': `10.12.${__VU}.${__ITER % 250}`,
      },
    },
  );
}

function verify(token, code) {
  return http.post(
    'http://localhost:8082/api/v1/auth/mfa/verify',
    JSON.stringify({ mfa_token: token, backup_code: code }),
    {
      headers: {
        'Content-Type': 'application/json',
        'X-Request-ID': `bkv-${__VU}-${__ITER}-${Date.now()}`,
        'X-Forwarded-For': `10.13.${__VU}.${__ITER % 250}`,
      },
    },
  );
}

export default function () {
  const idx = (__VU * 120 + __ITER) % codes.length;
  const c = codes[idx];
  const r = Math.random();
  if (r < 0.7) {
    // Válido 1 uso (cada código se usa una vez).
    const lr = login(c.email);
    if (lr.status !== 202) {
      check(lr, { '202': () => false });
      return;
    }
    const vr = verify(lr.json().data.mfa_token, c.code);
    check(vr, { '200': (x) => x.status === 200 });
    if (vr.status === 200) validTrend.add(vr.timings.duration);
  } else if (r < 0.85) {
    // Reuso: consume primero y repite con challenge nuevo.
    const lr = login(c.email);
    if (lr.status !== 202) return;
    const t1 = lr.json().data.mfa_token;
    const v1 = verify(t1, c.code);
    if (v1.status !== 200) return;
    const lr2 = login(c.email);
    if (lr2.status !== 202) return;
    const v2 = verify(lr2.json().data.mfa_token, c.code);
    check(v2, { '401 replay': (x) => x.status === 401 });
    if (v2.status === 401) invalidTrend.add(v2.timings.duration);
  } else {
    // TOTP malo (misma métrica anti-oráculo tipo).
    const lr = login(c.email);
    if (lr.status !== 202) return;
    const vr = verify(lr.json().data.mfa_token, '000000');
    check(vr, { '401': (x) => x.status === 401 });
    if (vr.status === 401) invalidTrend.add(vr.timings.duration);
  }
}
