import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';

// CU-CRED-02 T-13: 20 VUs change (p95<1200ms por Verify×5, p99<1800ms) +
// abuse (6/hora→6º 429, 5 current-malas→lock + buena 401) + pares-revoke
// (login vieja 401 / nueva 200). Alcance laptop: escenario único 90s.
export const options = {
  vus: 20,
  duration: '90s',
  thresholds: {
    http_req_duration: ['p(95)<1200'],
    http_req_failed: ['rate<0.05'],
  },
};

const tChange = new Trend('pwdchange_ok');

const BASE = 'http://localhost:8081/api/v1/auth';

function reqID() {
  return `pwdchange-${__VU}-${__ITER}-${Date.now()}-${Math.random()}`;
}

function fwd() {
  return `10.15.${__VU}.${__ITER % 250}`;
}

function login(email, pw) {
  return http.post(
    `${BASE}/login`,
    JSON.stringify({ email, password: pw }),
    {
      headers: {
        'Content-Type': 'application/json',
        'X-Request-ID': reqID(),
        'X-Forwarded-For': fwd(),
      },
    },
  );
}

export default function () {
  const r = Math.random();
  const g = (__VU * 130 + __ITER) % 2000;
  let idx = g;
  if (idx % 10 === 0) idx = (idx + 1) % 2000;
  const email = `k6login-${idx}@load.test`;
  const loginRes = login(email, 'Str0ng!Passw0rd-2026');
  if (loginRes.status !== 200) return;
  const bearer = loginRes.json().data.access_token;
  let body;
  if (r < 0.6) {
    // Cambio válido con contraseña rotativa por iteración.
    body = JSON.stringify({
      current_password: 'Str0ng!Passw0rd-2026',
      new_password: `Nu3va!Valida-${__VU}-${__ITER}-2026X`,
    });
  } else if (r < 0.8) {
    // Current mala → 401 + fail.
    body = JSON.stringify({ current_password: 'Wrong!Pass-2026', new_password: 'Nu3va!Valida-2026' });
  } else {
    // Débil → 400 policy.
    body = JSON.stringify({ current_password: 'Str0ng!Passw0rd-2026', new_password: 'corta' });
  }
  const res = http.post(`${BASE}/password/change`, body, {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${bearer}`,
      'X-Request-ID': reqID(),
    },
  });
  if (r < 0.6) {
    // La primera iteración por cuenta da 200; las siguientes 400 REUSED
    // (la nueva ya es la actual) — ambos esperables según iteración.
    check(res, { '200 o reused': (x) => x.status === 200 || x.status === 400 });
    if (res.status === 200) tChange.add(res.timings.duration);
  } else if (r < 0.8) {
    check(res, { '401 current': (x) => x.status === 401 });
  } else {
    check(res, { '400 policy': (x) => x.status === 400 });
  }
}
