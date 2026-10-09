import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';
import { SharedArray } from 'k6/data';
import { createHMAC } from 'k6/crypto';

// CU-AUTH-02 T-13: login-202 + TOTP real (HMAC-SHA1 RFC4226 en JS) + verify.
// 25 VUs 60s; replay/wrong-code → 401; |p50(valid)-p50(invalid)|<50ms.
const users = new SharedArray('mfa-users', () =>
  JSON.parse(open('./mfa_users.json')),
);

export const options = {
  vus: 25,
  duration: '60s',
  thresholds: {
    http_req_duration: ['p(95)<3000'],
  },
};

const validTrend = new Trend('mfa_valid_duration');
const invalidTrend = new Trend('mfa_invalid_duration');

function hexToBytes(hex) {
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < b.length; i++) {
    b[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return b;
}

function totp(secretHex, counter) {
  const key = hexToBytes(secretHex);
  const msg = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    msg[i] = c & 0xff;
    c = Math.floor(c / 256);
  }
  const h = createHMAC('sha1', key);
  h.update(msg);
  const digest = h.digest('hex');
  const bytes = hexToBytes(digest);
  const offset = bytes[bytes.length - 1] & 0x0f;
  const code =
    ((bytes[offset] & 0x7f) << 24) |
    (bytes[offset + 1] << 16) |
    (bytes[offset + 2] << 8) |
    bytes[offset + 3];
  return String(code % 1000000).padStart(6, '0');
}

function login(email) {
  const res = http.post(
    'http://localhost:8080/api/v1/auth/login',
    JSON.stringify({ email: email, password: 'Str0ng!Passw0rd-2026' }),
    {
      headers: {
        'Content-Type': 'application/json',
        'X-Request-ID': `mfa-${__VU}-${__ITER}-${Date.now()}`,
        'X-Forwarded-For': `10.9.${__VU}.${__ITER % 250}`,
      },
    },
  );
  return res;
}

export default function () {
  const idx = (__VU * 80 + __ITER) % users.length;
  const u = users[idx];
  const email = `mfa-${Math.floor(idx)}@load.test`;
  const lr = login(email);
  if (lr.status !== 202) {
    check(lr, { '202': () => false });
    return;
  }
  const mfaToken = lr.json().data.mfa_token;
  const r = Math.random();
  let code;
  if (r < 0.8) {
    const counter = Math.floor((Date.now() / 1000 + 5) / 30);
    code = totp(u.secret_hex, counter);
  } else if (r < 0.9) {
    code = '000000'; // inválido
  } else {
    // Replay: código válido actual (se verifica dos veces con challenges distintos).
    const counter = Math.floor((Date.now() / 1000 + 5) / 30);
    code = totp(u.secret_hex, counter);
  }
  const vr = http.post(
    'http://localhost:8080/api/v1/auth/mfa/verify',
    JSON.stringify({ mfa_token: mfaToken, code: code }),
    {
      headers: {
        'Content-Type': 'application/json',
        'X-Request-ID': `vfy-${__VU}-${__ITER}-${Date.now()}`,
        'X-Forwarded-For': `10.10.${__VU}.${__ITER % 250}`,
      },
    },
  );
  if (r < 0.8) {
    check(vr, { '200': (x) => x.status === 200 });
    if (vr.status === 200) validTrend.add(vr.timings.duration);
  } else if (r < 0.9) {
    check(vr, { '401': (x) => x.status === 401 });
    if (vr.status === 401) invalidTrend.add(vr.timings.duration);
  } else {
    // Replay real: mismo código válido con challenge NUEVO → 401 replay_blocked.
    check(vr, { '200 primero': (x) => x.status === 200 });
    const lr2 = login(email);
    if (lr2.status === 202) {
      const t2 = lr2.json().data.mfa_token;
      const vr2 = http.post(
        'http://localhost:8080/api/v1/auth/mfa/verify',
        JSON.stringify({ mfa_token: t2, code: code }),
        {
          headers: {
            'Content-Type': 'application/json',
            'X-Request-ID': `rpl-${__VU}-${__ITER}-${Date.now()}`,
            'X-Forwarded-For': `10.11.${__VU}.${__ITER % 250}`,
          },
        },
      );
      check(vr2, { '401 replay': (x) => x.status === 401 });
      if (vr2.status === 401) invalidTrend.add(vr2.timings.duration);
    }
  }
}
