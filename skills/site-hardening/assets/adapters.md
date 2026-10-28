# Wiring shield.mjs into each stack

Copy `shield.mjs` into the project first. Each block below is the whole integration.

## Astro (SSR, `output: 'server'`)

`src/middleware.ts`. Turn Astro's own `security.checkOrigin` off in `astro.config` only if it
misreads the host behind your proxy; this guard replaces it.

```ts
import { defineMiddleware, sequence } from 'astro:middleware';
import { crossSiteRefused, securityHeaders, publicOrigin } from './lib/shield.mjs';

const shield = defineMiddleware(async (ctx, next) => {
  if (crossSiteRefused(ctx.request, ctx.url)) return new Response('Forbidden', { status: 403 });
  const res = await next();
  const { proto } = publicOrigin(ctx.request, ctx.url);
  for (const [k, v] of Object.entries(securityHeaders({ proto }))) res.headers.set(k, v);
  return res;
});

export const onRequest = sequence(shield /* , your auth gate */);
```

In an API route:

```ts
import { clientIp, limited, HOUR } from '../../lib/shield.mjs';
const ip = clientIp(request);
if (limited('signup:' + ip, 5, HOUR) || limited('signup:*', 60, HOUR)) return new Response(null, { status: 429 });
```

## Astro (static) and other static hosts

No server, so no headers from code. Put a `<meta http-equiv="Content-Security-Policy">` in the
layout, and send real headers from the host (Vercel `vercel.json`, Netlify `_headers`, Cloudflare
rules). DigitalOcean static sites can't send custom headers at all. A form on a static page posts
to a server you own, never to a database table the public key can write.

## Express

```js
import { clientIp, crossSiteRefused, securityHeaders, publicOrigin, limited, HOUR } from './shield.mjs';

app.set('trust proxy', true);
app.disable('x-powered-by');
app.use((req, res, next) => {
  if (crossSiteRefused(req)) return res.status(403).json({ error: 'Forbidden' });
  res.set(securityHeaders({ proto: publicOrigin(req).proto }));
  next();
});
const cap = (bucket, perIp, site, win) => (req, res, next) =>
  limited(`${bucket}:${clientIp(req, req.socket.remoteAddress)}`, perIp, win) || limited(`${bucket}:*`, site, win)
    ? res.status(429).json({ error: 'Too many requests' }) : next();
app.post('/api/contact', cap('contact', 3, 20, HOUR), handler);
```

## Next.js (App Router)

`next.config`:

```ts
const nextConfig = {
  poweredByHeader: false,
  async headers() {
    return [{ source: '/:path*', headers: Object.entries(securityHeaders({ proto: 'https' })).map(([key, value]) => ({ key, value })) }];
  },
};
```

Browsers ignore HSTS over plain http, so a static `https` here doesn't affect local dev. If some
pages are embedded on partner sites, give `X-Frame-Options` its own rule that skips them, e.g.
`source: '/((?!embed).*)'`. Rate limits and the cross-site guard go in route handlers or in
`middleware.ts` / `proxy.ts`.

## Plain Node `http`

```js
const server = createServer((req, res) => {
  for (const [k, v] of Object.entries(securityHeaders({ proto: publicOrigin(req).proto }))) res.setHeader(k, v);
  if (crossSiteRefused(req)) { res.writeHead(403); return res.end(); }
  if (req.method === 'POST' && limited('post:' + clientIp(req, req.socket.remoteAddress), 240, MINUTE)) { res.writeHead(429); return res.end(); }
  // …
});
```

## Supabase

- Row security on every table, and no policy that lets the public key write a table that something
  else trusts (leads, logs, waitlists). Write those from the server with the secret key.
- Never ship the secret key to a browser bundle. Check after a build:
  `grep -rE "sb_secret_|service_role" dist/ .next/static/ 2>/dev/null`.
- If a server-side insert can fail, make the form say so. A form that shows success on failure
  loses sign-ups silently when the project moves or is paused.

## The forensic log and alerts (any stack)

```js
import { attemptRow, spikeAlert, formToken, honeypotFilled, requestLooksForged, looksLikeBot, limited, HOUR } from './shield.mjs';
import { Blocklist } from './blocklist.mjs';

const block = new Blocklist({ url: process.env.BLOCKLIST_URL });
const token = formToken(process.env.FORM_SECRET);
const alerts = spikeAlert({ thresholds: { dropped: 30, accepted: 8 }, send: (kind, n, d) => mailOwner(`${n} ${kind} in the last hour`, d) });

async function intake(req, body) {
  const drop = (why) => {
    void db.from('attempts').insert(attemptRow(req, { site: 'example.com', form: '/api/intake', body, reason: why, secret: process.env.FORM_SECRET }));
    void alerts.note('dropped', why);
    return json({ ok: true });                       // a bot learns nothing
  };
  const ip = clientIp(req);
  if (block.has(ip)) return drop('blocked range');
  if (honeypotFilled(body)) return drop('honeypot');
  const forged = requestLooksForged(req); if (forged) return drop(forged);
  const tok = token.verify(body.t); if (!tok.ok) return drop(tok.why);
  const bot = looksLikeBot(body); if (bot) return drop(bot);
  if (limited('intake:' + ip, 3, HOUR) || limited('intake:*', 20, HOUR)) return drop('rate');
  // …store the lead, then:
  void db.from('attempts').insert(attemptRow(req, { site: 'example.com', form: '/api/intake', body, reason: 'accepted', secret: process.env.FORM_SECRET }));
  void alerts.note('accepted', body.email);
}
```

Mint the token where the form renders (`token.mint()` into a hidden field named `t`).

## Paid models

```js
import { tierBudget } from './shield.mjs';
const MODELS = { default: 'claude-haiku-5-5', premium: 'claude-sonnet-5-5' };   // the server owns this map
const ai = tierBudget({ default: Number(process.env.CHAT_DAILY_CAP || 500), premium: Number(process.env.CHAT_PREMIUM_DAILY_CAP || 40) },
  { onWarn: (tier, used, cap) => mailOwner(`chat ${tier} at ${used}/${cap} today`) });
const tier = ai.pick(body.tier);
if (!tier) return json({ error: 'Taken a lot of calls today. Try tomorrow.' }, 429);
const model = MODELS[tier];
```

## The live check in Shipmate's sentinel

The sentinel already probes every project's `health_url` every five minutes. Add a `security`
block to the project's `.shipmate.yml`:

```yaml
security:
  form: /api/contact
  resolve: your-project-ref.supabase.co
  mail: example.com
  embed: /embed
```

and a `security` check in `sentinel.sh` that runs
`node ~/.claude/skills/site-hardening/assets/check.mjs "$url" --json` with those flags and reports
each `ok: false` result as a problem that just opened, the way the `site` check does. Leave
`--limits` out of the timer; run it by hand after a deploy. Until the sentinel carries it, a
weekly run by hand across every live domain is the floor.
