import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';
import exec from 'k6/execution';

// CU-SES-03 T-13: por iteración login×2 (A=current, B=target) + lista +
// revoke-B + repeat-404 + actual-400. Bulk (20 sesiones) cubierto en el
// test de integración PG (determinista); aquí concurrencia + latencias.
// Pool k6s-* fresco por corrida (buckets login:account 5/min,
// sessions:list 60/min, revoke-one 20/hora acumulan entre corridas).
// Umbrales: list p95<120ms PG, revoke p95<200ms, checks 100%.
// Uso: k6 run --vus 8 --duration 40s scripts/load/sessions_smoke.js
export const options = {
  vus: 20,
  duration: '60s',
  thresholds: {
    checks: ['rate==1.0'],
  },
};

const tList = new Trend('sessions_list');
const tRevoke = new Trend('sessions_revoke');

const BASE = 'http://localhost:8080/api/v1/auth';

function reqID(p) {
  return `ses-${p}-${exec.scenario.iterationInTest}-${Date.now()}-${Math.random()}`;
}

export default function () {
  // Índice global-único ( __ITER es local-por-VU y compartiría usuarios
  // entre VUs falseando rate-limits — lección CU-SES-02).
  const idx = exec.scenario.iterationInTest % 2000;
  const email = `k6s-${idx % 200}@load.test`;
  const fwd = `10.27.${exec.scenario.iterationInTest % 250}.${idx % 250}`;

  function login() {
    return http.post(
      `${BASE}/login`,
      JSON.stringify({ email: email, password: 'Str0ng!Passw0rd-2026' }),
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Request-ID': reqID('login'),
          'X-Forwarded-For': fwd,
          'X-Client-Type': 'native',
        },
      },
    );
  }

  const rA = login();
  if (rA.status !== 200) return;
  const tokA = rA.json().data.access_token;
  const sidA = rA.json().data.sid;
  const rB = login();
  if (rB.status !== 200) return;
  const sidB = rB.json().data.sid;

  // Lista: 200 + total≥2 + current==A.
  const list = http.get(`${BASE}/sessions`, {
    headers: { Authorization: `Bearer ${tokA}`, 'X-Request-ID': reqID('list'), 'X-Forwarded-For': fwd },
  });
  check(list, { '200 list': (x) => x.status === 200 });
  if (list.status === 200) {
    tList.add(list.timings.duration);
    const body = list.json();
    check(list, {
      'total>=2': () => body.data.total >= 2,
      'current==A': () => body.data.sessions.some((s) => s.current === true && s.sid === sidA),
      'sin-secretos': () => JSON.stringify(body).indexOf('jti') < 0 && JSON.stringify(body).indexOf('family') < 0,
    });
  }

  // Revoca B con A → 200; repeat → 404; actual → 400.
  const del = http.del(`${BASE}/sessions/${sidB}`, null, {
    headers: { Authorization: `Bearer ${tokA}`, 'X-Request-ID': reqID('del'), 'X-Forwarded-For': fwd },
  });
  check(del, { '200 revoked': (x) => x.status === 200 });
  if (del.status === 200) tRevoke.add(del.timings.duration);

  const rep = http.del(`${BASE}/sessions/${sidB}`, null, {
    headers: { Authorization: `Bearer ${tokA}`, 'X-Request-ID': reqID('rep'), 'X-Forwarded-For': fwd },
  });
  check(rep, { '404 repeat': (x) => x.status === 404 });

  const self = http.del(`${BASE}/sessions/${sidA}`, null, {
    headers: { Authorization: `Bearer ${tokA}`, 'X-Request-ID': reqID('self'), 'X-Forwarded-For': fwd },
  });
  check(self, { '400 actual': (x) => x.status === 400 });
}
