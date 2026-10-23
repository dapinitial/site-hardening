# Content Security Policy, the procedure

The strongest header and the one that breaks pages, so it goes in three steps instead of one.
The portal (portal.unakin.com) is the finished example: enforcing, `script-src 'self'`, no inline
scripts, violations reported to `/api/csp-report`.

## 1. Report only

Ship the policy as `Content-Security-Policy-Report-Only` with a report endpoint. Nothing is
blocked; the browser tells you what would have been.

```
default-src 'self';
script-src 'self';
style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
font-src 'self' https://fonts.gstatic.com data:;
img-src 'self' data: blob: https:;
connect-src 'self' https://<project>.supabase.co wss://<project>.supabase.co;
frame-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none';
report-uri /api/csp-report
```

The report endpoint takes `application/csp-report` and `application/reports+json`, is exempt
from the cross-site guard (the browser posts it with no Origin), is rate limited, and logs
`document-uri`, `blocked-uri`, `violated-directive` and `script-sample`. Nothing else.

## 2. Move inline code out

Every violation on your own pages is an inline `<script>`, an `onclick=`, or `javascript:` link.
Move each into a file under `/public/js` and load it with `<script src>`. Frameworks with a build
step (Astro, Next) can emit per-script hashes instead; Sedulous uses Astro's `experimental.csp`
for that. Styles can keep `'unsafe-inline'` for now: scoped styles are pervasive and low-risk.

Third-party embeds get named, never wildcarded: `frame-src https://www.youtube-nocookie.com`,
`media-src https://*.dropboxusercontent.com`. If a page needs WebAssembly, `'wasm-unsafe-eval'`
on `script-src` only, and only on that route (davidpuerto.com scopes it to `/cursorlab`).

## 3. Enforce

When the report log is quiet for a week, rename the header to `Content-Security-Policy`. Keep
the report endpoint: it's how you learn a deploy broke something before a visitor tells you.

## Static hosts

No server, so the policy goes in a `<meta http-equiv="Content-Security-Policy">` in the layout.
Meta policies can't carry `frame-ancestors` or `report-uri`, so a static site gets framing
protection only from a proxy or the host's header rules.
