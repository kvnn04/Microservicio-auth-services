import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';

// CU-SES-02 T-13: por iteración login (1 sesión fresca) + corte global.
// El caso bulk (20 sesiones/user) se cubre en el test de integración PG
// (determinista); aquí concurrencia + latencia del corte.
// Pool 200 (k6login-0..199@load.test ACTIVE, sin MFA: se evita %10==0).
// Umbrales: corrección funcional (checks 100%). El p95<300ms del plan se
// mide sobre global_ok SIN Argon2 concurrente idealmente; con login+global
// mezclados el Argon2 domina — se reporta y se compara con logout_iso.
// Uso típico: k6 run --vus 10 --duration 45s scripts/load/logout_global_smoke.js
export const options = {
  vus: 20,
  duration: '60s',
  thresholds: {
    checks: ['rate==1.0'],
  },
};

const tGlobal = new Trend('global_ok');

const BASE = 'http://localhost:8080/api/v1/auth';

function reqID(p) {
  return `glo-${p}-${__VU}-${__ITER}-${Date.now()}-${Math.random()}`;
}

export default function () {
  const g = (__VU * 130 + __ITER) % 200;
  let idx = g;
  if (idx % 10 === 0) idx = (idx + 1) % 200;
  // Pool k6g-* (fresco por corrida: los buckets horarios 5/h-user y
  // login:account 5/min acumulan entre corridas y falsean 429).
  const email = `k6g-${idx}@load.test`;

  const loginRes = http.post(
    `${BASE}/login`,
    JSON.stringify({ email: email, password: 'Str0ng!Passw0rd-2026' }),
    {
      headers: {
        'Content-Type': 'application/json',
        'X-Request-ID': reqID('login'),
        'X-Forwarded-For': `10.24.${__VU}.${__ITER % 250}`,
        'X-Client-Type': 'native',
      },
    },
  );
  if (loginRes.status !== 200) return;
  let bearer;
  try {
    bearer = loginRes.json().data.access_token;
  } catch (e) {
    return;
  }
  if (!bearer) return;

  // Corte global (mata la recién creada + restos del user).
  const res = http.post(`${BASE}/logout-global`, null, {
    headers: {
      Authorization: `Bearer ${bearer}`,
      'X-Request-ID': reqID('global'),
      'X-Forwarded-For': `10.24.${__VU}.${__ITER % 250}`,
    },
  });
  check(res, { '200 global': (x) => x.status === 200 });
  if (res.status === 200) tGlobal.add(res.timings.duration);
  check(res, {
    'clear-cookie': (x) => {
      const sc = x.headers['Set-Cookie'] || x.headers['set-cookie'] || '';
      return sc.indexOf('refresh_token=') >= 0 && sc.indexOf('Path=/api/v1/auth/refresh') >= 0;
    },
  });

  // Repeat mismo Bearer (nuevo RequestID) → 200 con 0.
  const replay = http.post(`${BASE}/logout-global`, null, {
    headers: {
      Authorization: `Bearer ${bearer}`,
      'X-Request-ID': reqID('replay'),
      'X-Forwarded-For': `10.24.${__VU}.${__ITER % 250}`,
    },
  });
  check(replay, { '200 repeat-0': (x) => x.status === 200 });
}
