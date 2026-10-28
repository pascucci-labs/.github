import http from 'k6/http';
import { check, sleep } from 'k6';
export const options = {
  vus: 1,
  duration: '15s',
  thresholds: { http_req_duration: ['p(95)<500'], http_req_failed: ['rate<0.01'] },
};
export default function () {
  const result = http.get(__ENV.TARGET_URL, { redirects: 0 });
  check(result, { 'successful response': r => r.status >= 200 && r.status < 300 });
  sleep(1);
}
