// shield.mjs — the baseline every site gets from its first commit.
// Framework-agnostic: works on any Web `Request` (Astro, Next route handlers, Hono, Workers)
// and on Node's IncomingMessage through the small `headersOf` shim. No dependencies.
//
// Built from what held and what broke across the fleet, Sept to Oct 2026:
//   - a botnet on rented proxies drove headless Chromium at the unakin.com intake form for a month
//     (2,126 attempts, 107 addresses, 271 target domains) trying to make its reply email a relay;
//   - three servers read the leftmost X-Forwarded-For, which the visitor writes;
//   - two apps sent mail to unverified addresses with no site-wide ceiling;
//   - one admin page treated "no key configured" as "no gate".
// Copy this file into the project (src/lib/shield.mjs or similar). Every export is small enough
// to read before you trust it.

import { createHmac, createHash, timingSafeEqual } from 'node:crypto';

/* ------------------------------------------------------------------ headers in */

/** Read a header from a Web Request, a Headers object, or a Node IncomingMessage. */
export function headersOf(req) {
  const h = req?.headers;
  if (h && typeof h.get === 'function') return (k) => h.get(k);
  return (k) => { const v = h?.[k.toLowerCase()]; return Array.isArray(v) ? v[0] : v ?? null; };
}

/** The client's real address. DigitalOcean's edge sets do-connecting-ip and Cloudflare sets
 * cf-connecting-ip; both overwrite any copy a visitor sends. The LEFTMOST X-Forwarded-For entry
 * is whatever the visitor wrote, so it is never trusted: behind one proxy hop the client is the
 * second-to-last entry. Pass `socket` (Node) as the last resort. */
export function clientIp(req, socketAddress) {
  const get = headersOf(req);
  const direct = get('do-connecting-ip')?.trim() || get('cf-connecting-ip')?.trim();
  if (direct) return direct;
  const parts = String(get('x-forwarded-for') ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  if (parts.length >= 2) return parts[parts.length - 2];
  return parts[0] || socketAddress || 'unknown';
}

/** The public host and protocol, as the visitor used them (proxies rewrite Host and talk plain http). */
export function publicOrigin(req, fallbackUrl) {
  const get = headersOf(req);
  const url = fallbackUrl ? new URL(fallbackUrl) : null;
  const hosts = [get('x-forwarded-host'), get('host'), url?.host].filter(Boolean).map((x) => String(x).split(',')[0].trim());
  const proto = String(get('x-forwarded-proto') ?? url?.protocol?.replace(':', '') ?? 'http').split(',')[0].trim();
  return { hosts, proto };
}

/* ------------------------------------------------------------------ headers out */

/** The security headers. HSTS only when the visitor arrived over https (pass `proto` from
 * publicOrigin: behind a proxy the app's own URL always says http, and HSTS silently never ships).
 * Permissions: list only what the site really uses, e.g. { geolocation: '(self)' }. Add a CSP on
 * top when the page's scripts allow it; it is the strongest of these and the one that needs care. */
export function securityHeaders({ proto = 'https', frame = 'SAMEORIGIN', permissions = {} } = {}) {
  const perms = { camera: '()', microphone: '()', geolocation: '()', payment: '()', ...permissions };
  const out = {
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': Object.entries(perms).map(([k, v]) => `${k}=${v}`).join(', '),
  };
  if (frame) out['X-Frame-Options'] = frame;
  if (proto === 'https') out['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
  return out;
}

/* ------------------------------------------------------------------ cross-site guard */

/** True when a state-changing request came from another site: an Origin naming a host that
 * isn't ours, or a browser labelling the fetch cross-site. Scripts send neither and pass on to
 * the rate limits; this stops another page driving a visitor's signed-in browser. Framework
 * origin checks often misread the host behind a proxy and get switched off; this one doesn't. */
export function crossSiteRefused(req, fallbackUrl) {
  const get = headersOf(req);
  const method = String(req.method ?? 'GET').toUpperCase();
  if (['GET', 'HEAD', 'OPTIONS'].includes(method)) return false;
  const { hosts } = publicOrigin(req, fallbackUrl);
  const origin = get('origin');
  let originHost = null;
  if (origin) { try { originHost = new URL(origin).host; } catch { originHost = '!'; } }
  return (originHost !== null && !hosts.includes(originHost)) || get('sec-fetch-site') === 'cross-site';
}

/* ------------------------------------------------------------------ rate limits */

const windows = new Map();

/** Sliding window. True when `key` already has `max` hits in `windowMs` (this hit isn't counted).
 * Always pair a per-address key with a site-wide one: a botnet rotating addresses walks straight
 * past per-address limits (unakin.com saw 107 addresses in a month).
 *   if (limited('contact:' + ip, 3, HOUR) || limited('contact:*', 20, HOUR)) → 429 */
export function limited(key, max, windowMs, now = Date.now()) {
  const hits = (windows.get(key) ?? []).filter((t) => now - t < windowMs);
  if (hits.length >= max) { windows.set(key, hits); return true; }
  hits.push(now);
  windows.set(key, hits);
  if (windows.size > 10_000) for (const [k, v] of windows) if (!v.some((t) => now - t < 3_600_000)) windows.delete(k);
  return false;
}
export const MINUTE = 60_000, HOUR = 3_600_000, DAY = 86_400_000;

/** A shared budget of units (recipients, AI calls) over a rolling window: take() is false, and
 * nothing is drawn, when the draw would go over. Use it for anything that spends money or
 * reputation: an outgoing mail relay, a paid model, a third-party API. */
export function budget(cap, windowMs = DAY) {
  const draws = [];
  return {
    take(units = 1, now = Date.now()) {
      while (draws.length && now - draws[0][0] > windowMs) draws.shift();
      const used = draws.reduce((n, [, u]) => n + u, 0);
      if (used + units > cap) return false;
      draws.push([now, units]);
      return true;
    },
  };
}

/* ------------------------------------------------------------------ secrets */

/** Constant-time string comparison (a plain === leaks how many leading characters matched). */
export function safeEqual(given, want) {
  if (typeof given !== 'string' || typeof want !== 'string' || !want) return false;
  const a = Buffer.from(given), b = Buffer.from(want);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Gate on a configured key that FAILS CLOSED: with no key set in production, nobody gets in.
 * The bug this prevents: `if (key && given !== key) deny` lets everyone in when key is unset. */
export function keyGate(given, configured, { production = process.env.NODE_ENV === 'production' } = {}) {
  if (!configured) return !production;
  return safeEqual(given, configured);
}

/* ------------------------------------------------------------------ form gates */

/** A signed token minted when the form renders. It proves the page was loaded (bots posting JSON
 * at the API never did) and that a person took at least `minMs` to fill it in. */
export function formToken(secret) {
  if (!secret) throw new Error('formToken needs a secret');
  const sign = (ts) => createHmac('sha256', secret).update('form:' + ts).digest('hex').slice(0, 32);
  return {
    mint: () => { const ts = String(Date.now()); return `${ts}.${sign(ts)}`; },
    verify(tok, { minMs = 4_000, maxMs = DAY } = {}) {
      if (typeof tok !== 'string') return { ok: false, why: 'no token' };
      const [ts, sig] = tok.split('.');
      if (!ts || !sig || !safeEqual(sig, sign(ts))) return { ok: false, why: 'bad token' };
      const age = Date.now() - Number(ts);
      if (!(age > minMs)) return { ok: false, why: 'too fast' };
      if (age > maxMs) return { ok: false, why: 'stale token' };
      return { ok: true };
    },
  };
}

/** Honeypot: a field real people never see or fill (hide it with CSS, name it something tempting
 * like `website` or `company`). Answer a filled one with the normal success response. */
export const honeypotFilled = (body, field = 'website') => typeof body?.[field] === 'string' && body[field].trim().length > 0;

/** Header shapes no real browser produces. Learned from the 2026-09 botnet: headless Chromium that
 * sends Chrome's client hints while claiming a 2005 browser, and never sends Accept-Language. */
export function requestLooksForged(req) {
  const get = headersOf(req);
  const ua = get('user-agent') ?? '';
  if (get('sec-ch-ua') && !/Chrome\//.test(ua)) return 'ua contradicts client hints';
  if (!get('accept-language')) return 'no accept-language';
  return null;
}

/** Content only a bot writes: random 8–14 character mixed-case-and-digit names, a "message" that
 * is one unbroken token, a link dump. Returns a reason, or null. Tune `fields` to the form. */
export function looksLikeBot({ name = '', company = '', message = '' } = {}) {
  const random = (s) => /^[A-Za-z0-9]{8,14}$/.test(s) && /[0-9]/.test(s) && /[a-z]/.test(s) && /[A-Z]/.test(s);
  if (random(name) && random(company)) return 'random name and company';
  const words = message.trim().split(/\s+/);
  if (words.length === 1 && message.length > 15 && !/^(https?:\/\/|www\.)\S+$/i.test(message) && !/^\S+@\S+\.\S+$/.test(message)) return 'one unbroken token';
  if ((message.match(/https?:\/\//g) ?? []).length >= 3) return 'link dump';
  return null;
}

/* ------------------------------------------------------------------ the relay rule */

/** Mail to an address the sender typed is mail to a stranger until that address is verified.
 * So an acknowledgement carries NOTHING the sender wrote: no name, no quote, no subject line from
 * the form. Build it from fixed text only; this helper exists so the rule has a name in code. */
export const ackEmail = ({ subject, text }) => ({ subject, text });

/** A stable, keyed hash for logging an address without storing it. */
export const hashFor = (secret, value) => createHash('sha256').update(`${secret}|${String(value).trim().toLowerCase()}`).digest('hex').slice(0, 24);
