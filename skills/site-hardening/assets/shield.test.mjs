import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  clientIp, publicOrigin, securityHeaders, crossSiteRefused, limited, budget, safeEqual, keyGate,
  formToken, honeypotFilled, requestLooksForged, looksLikeBot,
} from './shield.mjs';

const req = (headers = {}, method = 'GET') => new Request('http://internal:8080/x', { method, headers });

test('clientIp trusts the edge header and never the leftmost forwarded entry', () => {
  assert.equal(clientIp(req({ 'do-connecting-ip': '9.9.9.9', 'x-forwarded-for': '6.6.6.6, 9.9.9.9, 10.0.0.1' })), '9.9.9.9');
  assert.equal(clientIp(req({ 'x-forwarded-for': '6.6.6.6, 1.2.3.4, 10.0.0.1' })), '1.2.3.4');
  assert.equal(clientIp(req({}), '127.0.0.1'), '127.0.0.1');
  // Node IncomingMessage shape
  assert.equal(clientIp({ headers: { 'cf-connecting-ip': '8.8.8.8' } }), '8.8.8.8');
});

test('HSTS follows how the visitor arrived, not the app URL', () => {
  const behindProxy = req({ 'x-forwarded-proto': 'https', 'x-forwarded-host': 'example.com' });
  assert.equal(publicOrigin(behindProxy, 'http://internal:8080/').proto, 'https');
  assert.ok(securityHeaders({ proto: 'https' })['Strict-Transport-Security']);
  assert.equal(securityHeaders({ proto: 'http' })['Strict-Transport-Security'], undefined);
  assert.match(securityHeaders({ permissions: { geolocation: '(self)' } })['Permissions-Policy'], /geolocation=\(self\)/);
});

test('cross-site guard: refuses other origins, passes our own and scripts', () => {
  const url = 'http://internal:8080/api';
  assert.equal(crossSiteRefused(req({ origin: 'https://evil.example', 'x-forwarded-host': 'example.com' }, 'POST'), url), true);
  assert.equal(crossSiteRefused(req({ 'sec-fetch-site': 'cross-site' }, 'POST'), url), true);
  assert.equal(crossSiteRefused(req({ origin: 'https://example.com', 'x-forwarded-host': 'example.com' }, 'POST'), url), false);
  assert.equal(crossSiteRefused(req({}, 'POST'), url), false);
  assert.equal(crossSiteRefused(req({ origin: 'https://evil.example' }, 'GET'), url), false);
});

test('limited: counts per key and stops at the ceiling', () => {
  const t = 1_000_000;
  for (let i = 0; i < 3; i++) assert.equal(limited('k1', 3, 1000, t + i), false);
  assert.equal(limited('k1', 3, 1000, t + 5), true);
  assert.equal(limited('k1', 3, 1000, t + 2000), false);
});

test('budget: shared, refuses the draw that would go over, frees with time', () => {
  const b = budget(50, 1000);
  assert.equal(b.take(25, 0), true);
  assert.equal(b.take(25, 1), true);
  assert.equal(b.take(1, 2), false);
  assert.equal(b.take(10, 1500), true);
});

test('keyGate fails closed in production and compares in constant time', () => {
  assert.equal(keyGate('anything', undefined, { production: true }), false);
  assert.equal(keyGate('anything', undefined, { production: false }), true);
  assert.equal(keyGate('right', 'right', { production: true }), true);
  assert.equal(keyGate('wrong', 'right', { production: true }), false);
  assert.equal(safeEqual('a', ''), false);
});

test('form token: signed, too fast is refused, tampering is refused', async () => {
  const f = formToken('s3cret');
  const tok = f.mint();
  assert.equal(f.verify(tok).why, 'too fast');
  assert.equal(f.verify(tok, { minMs: -1 }).ok, true);
  assert.equal(f.verify(tok.replace(/.$/, (c) => (c === '0' ? '1' : '0')), { minMs: -1 }).ok, false);
  assert.equal(f.verify(undefined).ok, false);
});

test('bot signals', () => {
  assert.equal(honeypotFilled({ website: 'x' }), true);
  assert.equal(honeypotFilled({}), false);
  assert.equal(requestLooksForged(req({ 'sec-ch-ua': '"Chromium"', 'user-agent': 'Mozilla/5.0 (X11; U; Win95) BonEcho/2.0', 'accept-language': 'en' })), 'ua contradicts client hints');
  assert.equal(requestLooksForged(req({ 'user-agent': 'curl/8' })), 'no accept-language');
  assert.equal(requestLooksForged(req({ 'user-agent': 'Mozilla/5.0 Chrome/130', 'sec-ch-ua': '"Chromium"', 'accept-language': 'en' })), null);
  assert.equal(looksLikeBot({ name: 'xK9mPqR2zL', company: 'Qw3rTy8UiO', message: 'hi' }), 'random name and company');
  assert.equal(looksLikeBot({ message: 'asdkjhqwkejhqwkjehqwkjeh' }), 'one unbroken token');
  assert.equal(looksLikeBot({ name: 'Ana', message: 'We need a new site for our bakery.' }), null);
});

import { tierBudget, spikeAlert, attemptRow } from './shield.mjs';
import { Blocklist } from './blocklist.mjs';

test('tierBudget: premium falls back to default when spent, warns once at 80%', () => {
  const warns = [];
  const ai = tierBudget({ default: 10, premium: 5 }, { windowMs: 1000, onWarn: (n, used, cap) => warns.push(`${n}:${used}/${cap}`) });
  const picks = []; for (let i = 0; i < 7; i++) picks.push(ai.pick('premium', 100 + i));
  assert.deepEqual(picks, ['premium', 'premium', 'premium', 'premium', 'premium', 'default', 'default']);
  assert.deepEqual(warns, ['premium:4/5']);
  assert.equal(ai.pick('nonsense', 200), 'default');
  for (let i = 0; i < 10; i++) ai.pick(undefined, 300 + i);
  assert.equal(ai.pick(undefined, 320), null);
  assert.equal(ai.pick(undefined, 2000), 'default');
});

test('spikeAlert fires once at the threshold, then stays silent', async () => {
  const sent = [];
  const a = spikeAlert({ thresholds: { dropped: 3 }, windowMs: 1000, silenceMs: 5000, send: async (k, n, d) => sent.push(`${k} ${n} ${d}`) });
  for (let i = 0; i < 6; i++) await a.note('dropped', 'x', 100 + i);
  assert.deepEqual(sent, ['dropped 3 x']);
  await a.note('dropped', 'later', 7000);
  assert.equal(sent.length, 1);               // under the threshold again after the window
  for (let i = 0; i < 3; i++) await a.note('dropped', 'again', 7001 + i);
  assert.equal(sent.length, 2);
});

test('attemptRow hashes the address and keeps only allowlisted headers', () => {
  const r = new Request('http://x/api/intake', { method: 'POST', headers: { 'user-agent': 'UA', 'accept-language': 'en', 'x-forwarded-for': '6.6.6.6, 1.2.3.4, 10.0.0.1', cookie: 'secret=1' } });
  const row = attemptRow(r, { site: 's', form: '/api/intake', body: { name: 'Bob', email: 'Target@Example.COM', website: 'spam', t: `${Date.now() - 5000}.sig` }, reason: 'honeypot', secret: 'k' });
  assert.equal(row.ip, '1.2.3.4');
  assert.equal(row.victim_domain, 'example.com');
  assert.equal(row.victim_hash.length, 24);
  assert.equal(row.headers.cookie, undefined);
  assert.equal(row.shape.honeypot, true);
  assert.ok(row.token_age_s >= 4.9 && row.token_age_s < 7);
  assert.ok(!JSON.stringify(row).includes('target@'));
});

test('blocklist matches v4 and v6 CIDRs and keeps the known-bad ranges', async () => {
  const b = new Blocklist({ ranges: ['10.1.0.0/16', '2001:db8::/32'] });
  assert.equal(b.has('95.134.17.9'), true);
  assert.equal(b.has('95.134.20.1'), false);
  assert.equal(b.has('10.1.200.3'), true);
  assert.equal(b.has('2001:db8:1::5'), true);
  assert.equal(b.has('2001:db9::1'), false);
  assert.equal(b.has('garbage'), false);
  const shared = new Blocklist({ url: 'https://list.example/x.json', fetchImpl: async () => ({ ok: true, json: async () => ['198.51.100.0/24'] }) });
  await shared.refresh();
  assert.equal(shared.has('198.51.100.7'), true);
  assert.equal(shared.has('95.134.17.9'), true);
  shared.stop();
});
