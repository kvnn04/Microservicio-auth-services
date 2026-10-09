import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';
import { SharedArray } from 'k6/data';

// CU-REG-06 T-13 (alcance documentado): initiate con Step-Up+password y list.
// El callback completo se cubre en E2E + k6 REG-04 (mismo costo OIDC).
const users = new SharedArray('link-users', () =>
  JSON.parse(open('./link_users.json')),
);

export const options = {
  vus: 10,
  duration: '45s',
  thresholds: {
    http_req_duration: ['p(95)<2500'],
  },
};

const initTrend = new Trend('link_initiate_duration');
const listTrend = new Trend('link_list_duration');

export default function () {
  const idx = (__VU * 300 + __ITER) % users.length;
  const u = users[idx];
  const auth = { Authorization: `Bearer ${u.token}` };
  if (u.pw) {
    const res = http.post(
      'http://localhost:8080/api/v1/auth/federated/google/link',
      JSON.stringify({ current_password: 'Str0ng!Passw0rd-2026' }),
      {
        headers: {
          ...auth,
          'Content-Type': 'application/json',
          'X-Request-ID': `link-${__VU}-${__ITER}-${Date.now()}`,
          'X-Forwarded-For': `10.6.${__VU}.${__ITER % 250}`,
        },
      },
    );
    check(res, { '200 initiate': (r) => r.status === 200 });
    if (res.status === 200) initTrend.add(res.timings.duration);
  } else {
    const res = http.get('http://localhost:8080/api/v1/auth/federated/linked', {
      headers: { ...auth, 'X-Forwarded-For': `10.7.${__VU}.${__ITER % 250}` },
    });
    check(res, { '200 list': (r) => r.status === 200 });
    if (res.status === 200) listTrend.add(res.timings.duration);
  }
}
