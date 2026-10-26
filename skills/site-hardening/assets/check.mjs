#!/usr/bin/env node
// check.mjs — the live check. Runs against a deployed site from outside and says what drifted.
//
//   node check.mjs https://example.com [--form /api/contact] [--resolve host,host] [--mail example.com]
//                  [--dkim selector] [--embed /embed] [--limits 6] [--json]
//
//   headers   the six security headers and no server/framework disclosure
//   form      (--form) a cross-site POST is refused (403) and a same-site one reaches validation
//   resolve   (--resolve) every third-party host the page depends on answers (a waitlist posting
//             to a database project that no longer exists looks fine from the page)
//   mail      (--mail) SPF and DMARC records exist on a sending domain (--dkim adds the selector)
//   embed     (--embed) paths meant to be framed by partners don't carry a same-origin frame rule
//   limits    (--limits N) N posts with a rotating forged X-Forwarded-For from this one address
//             still hit a 429. OFF by default: it spends N hits of the form's own caps, so run it
//             after a deploy, not every five minutes.
//
// Exit 1 when anything fails. --json prints one object for a sentinel to diff.
// No dependencies; Node 22+.

import { promises as dns } from 'node:dns';

const args = process.argv.slice(2);
const url = args.find((a) => a.startsWith('http'));
if (!url) { console.error('usage: check.mjs https://site [--form /path] [--resolve a,b] [--mail domain] [--dkim sel] [--embed /path] [--limits N] [--json]'); process.exit(2); }
const opt = (k) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : null; };
const flag = (k) => args.includes(k);
const base = new URL(url);
const results = [];
const add = (check, ok, detail, skipped = false) => results.push({ check, ok, skipped, detail });

const get = async (path, init = {}) => {
  const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), 15_000);
  try { return await fetch(new URL(path, base), { redirect: 'manual', signal: ctrl.signal, ...init }); }
  catch (e) { return { status: 0, headers: new Headers(), error: e.message }; }
  finally { clearTimeout(t); }
};

// ---- headers ----------------------------------------------------------------------------
{
  const res = await get('/');
  if (res.status === 0) add('reachable', false, res.error);
  else {
    add('reachable', res.status < 500, `${res.status}`);
    const h = res.headers;
    const want = {
      'strict-transport-security': (v) => /max-age=\d{6,}/.test(v),
      'x-content-type-options': (v) => /nosniff/i.test(v),
      'referrer-policy': (v) => v.length > 0,
      'permissions-policy': (v) => v.length > 0,
    };
    for (const [k, test] of Object.entries(want)) { const v = h.get(k); add(`header ${k}`, !!v && test(v), v ?? 'missing'); }
    // report-only counts: it is step 1 of the procedure, and it must run for a week without nagging
    const enforced = h.get('content-security-policy'); const reportOnly = h.get('content-security-policy-report-only');
    const csp = enforced ?? reportOnly;
    add('header content-security-policy', !!csp, csp ? (enforced ? '' : 'report-only: ') + csp.slice(0, 80) + (csp.length > 80 ? '…' : '') : 'missing (a meta CSP on the page is the fallback)');
    const xfo = h.get('x-frame-options'); const fa = csp && /frame-ancestors/.test(csp);
    add('framing', !!xfo || !!fa, xfo ?? (fa ? 'frame-ancestors in CSP' : 'neither X-Frame-Options nor frame-ancestors'));
    const disclose = ['x-powered-by', 'x-aspnet-version'].filter((k) => h.get(k)).map((k) => `${k}: ${h.get(k)}`);
    add('no framework disclosure', disclose.length === 0, disclose.join('; ') || 'none');
  }
}

// ---- form -------------------------------------------------------------------------------
const form = opt('--form');
if (form) {
  const post = (headers, body = '{}') => get(form, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body });
  const cross = await post({ origin: 'https://evil.example', 'sec-fetch-site': 'cross-site' });
  add('form refuses cross-site post', cross.status === 403, `${cross.status}`);
  const same = await post({ origin: base.origin, 'sec-fetch-site': 'same-origin' });
  // an empty body must reach validation (400/422), or a drop that answers like success (200/204)
  add('form reachable from our own page', [200, 204, 400, 422].includes(same.status), `${same.status}`);
  const n = Number(opt('--limits') ?? 0);
  if (n > 0) {
    const codes = [];
    for (let i = 0; i < n; i++) codes.push((await post({ 'x-forwarded-for': `203.0.113.${i + 1}` })).status);
    add('per-address limit survives a forged address', codes.includes(429), codes.join(' '));
  } else add('per-address limit survives a forged address', true, 'not run (pass --limits N after a deploy)', true);
} else add('form', true, 'no --form given', true);

// ---- resolve ----------------------------------------------------------------------------
for (const host of (opt('--resolve') ?? '').split(',').map((s) => s.trim()).filter(Boolean)) {
  try {
    await dns.lookup(host);
    const res = await (async () => { const c = new AbortController(); const t = setTimeout(() => c.abort(), 10_000); try { return await fetch(`https://${host}/`, { method: 'HEAD', signal: c.signal, redirect: 'manual' }); } finally { clearTimeout(t); } })();
    add(`depends on ${host}`, res.status > 0 && res.status < 500, `${res.status}`);
  } catch (e) { add(`depends on ${host}`, false, e.code ?? e.message); }
}

// ---- mail -------------------------------------------------------------------------------
const mail = opt('--mail');
if (mail) {
  const txt = async (name) => { try { return (await dns.resolveTxt(name)).map((r) => r.join('')); } catch { return []; } };
  const spf = (await txt(mail)).find((r) => /^v=spf1/i.test(r));
  add(`SPF on ${mail}`, !!spf, spf ?? 'missing');
  const dmarc = (await txt(`_dmarc.${mail}`)).find((r) => /^v=DMARC1/i.test(r));
  const monitoring = !!dmarc && /p=none/i.test(dmarc);
  add(`DMARC on ${mail}`, !!dmarc && !monitoring, dmarc ? dmarc + (monitoring ? '  (p=none only monitors; move to quarantine or reject once the reports look clean)' : '') : 'missing');
  const sel = opt('--dkim');
  if (sel) { const d = await txt(`${sel}._domainkey.${mail}`); add(`DKIM ${sel} on ${mail}`, d.some((r) => /v=DKIM1|p=/.test(r)), d.length ? 'present' : 'missing'); }
}

// ---- embed ------------------------------------------------------------------------------
const embed = opt('--embed');
if (embed) {
  const res = await get(embed);
  const xfo = res.headers.get('x-frame-options'); const csp = res.headers.get('content-security-policy') ?? '';
  const blocked = !!xfo || /frame-ancestors\s+'self'|frame-ancestors\s+'none'/.test(csp);
  add(`embed ${embed} stays frameable`, !blocked, xfo ?? (csp.match(/frame-ancestors[^;]*/)?.[0] ?? 'no frame rule'));
}

// ---- report -----------------------------------------------------------------------------
const failed = results.filter((r) => !r.ok && !r.skipped);
if (flag('--json')) console.log(JSON.stringify({ url, at: new Date().toISOString(), ok: failed.length === 0, results }));
else {
  console.log(`${url}`);
  for (const r of results) console.log(`  ${r.skipped ? '–' : r.ok ? '✓' : '✗'} ${r.check}  ${r.detail}`);
  console.log(failed.length ? `${failed.length} failing` : 'all clear');
}
process.exit(failed.length ? 1 : 0);
