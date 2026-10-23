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
