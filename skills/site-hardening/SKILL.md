---
name: site-hardening
description: The security baseline every website and web app gets from its first commit, and the audit that checks an existing one. Drops in shield.mjs (real client address, security headers, cross-site guard, per-address plus site-wide rate limits, spending budgets, fail-closed key gates, form gates against bots, the no-relay email rule) for Astro, Express, Next.js or plain Node. Use when starting any new site or app, adding a form, an email send, an admin page, an AI call or a public API route, or when the user says "harden this", "security review", "are we safe from bots", "audit the site", "lock this down". Fleet tool, works from any project directory.
---

# /site-hardening

Every site starts with this. It came out of one night in October 2026: a botnet spent a month trying
to turn the unakin.com contact form into a mail relay, and the sweep that followed found the same
handful of holes across the fleet. They were never exotic. They were defaults nobody revisited.

Two modes. **New site**: install the baseline before the first deploy. **Audit**: walk an existing
site through the checks below and fix what fails. Either way, do the work, test it, and commit;
push only when the user says to, because a push to main deploys.

## The baseline

`assets/shield.mjs` is one dependency-free module; `assets/adapters.md` wires it into Astro, Express,
Next.js and plain Node in a dozen lines each. Copy the module into the project, then:

1. **Real client address.** `clientIp(req)` reads the edge's own header (`do-connecting-ip`,
   `cf-connecting-ip`), never the leftmost `X-Forwarded-For`, which the visitor writes. Every rate
   limit keys on this.
2. **Security headers** on every response: HSTS, nosniff, frame policy, referrer policy, a
   permissions policy that allows only what the site uses. Read the protocol from
   `x-forwarded-proto`: behind a proxy the app's own URL always says http, and HSTS silently never
   ships. Drop `X-Powered-By`. Add a content security policy when the scripts allow it.
3. **Cross-site guard.** `crossSiteRefused(req)` on every state-changing request. Framework origin
   checks often misread the host behind a proxy and get switched off; this one compares against
   `x-forwarded-host` too.
4. **Two rate limits on every public write**: per address and site-wide. A botnet rotating addresses
   walks past per-address limits; the site-wide one is the ceiling.
5. **Budgets on anything that spends**: outgoing mail through your own account, paid AI models,
   third-party APIs that can ban your server. `budget(cap, DAY)`, shared across every user.
6. **Gates that fail closed.** `keyGate(given, process.env.ADMIN_KEY)`: no key configured in
   production means nobody gets in, not everybody.
7. **Form gates**, cheapest first: honeypot, signed render token with a 4-second minimum
   (`formToken`), `requestLooksForged`, `looksLikeBot`, then the rate limits. Answer every drop with
   the normal success response so a bot learns nothing, and log why.
8. **The relay rule.** Mail to an address someone typed goes to a stranger until it's verified, so
   it carries nothing they wrote: no name, no quote, no subject from the form.
9. **Gated content stays gated.** Every asset a protected page loads checks the same cookie as the
   page, especially when a public repo lists the asset names.
10. **Secrets out of git**, the secret key out of every browser bundle, row security on every table,
    and no public insert policy on a table something else trusts.
11. **Alerts with a ceiling**: tell the owner early about spikes, and cap the alerts themselves so
    they can never flood the inbox.

## The audit

Work one site at a time, and record each in the hardening log if the user keeps one.

1. **What's live.** Map repos to deployments (`doctl apps list`, the app spec's components and
   domains). Note the stack and whether the repo is public.
2. **From outside.** `curl -sD - -o /dev/null https://<domain>` and read the six headers and any
   `X-Powered-By`. Missing HSTS on an app that "sets" it means the protocol check is wrong.
3. **Every route.** List API routes and, for each: who may call it, what it writes, what it spends,
   what it sends, what it calls outside. Look hardest at routes that are public AND write, send or
   spend.
4. **The usual suspects.** Grep for `x-forwarded-for` (leftmost read), `checkOrigin: false` or
   origin checks against `Host`, `if (KEY && ...)` gates, `=== secret` comparisons, `sendMail` or
   provider sends to a user-supplied address, user text inside outgoing mail, model choice taken
   from the request, unbounded query parameters passed to third-party APIs, error messages from the
   provider returned to the browser, in-memory maps with no size bound.
5. **Settings beat comments.** Read the live environment (`doctl apps spec get <id> --format json`,
   keys only, never print secret values). A comment saying "disabled in production" is a claim;
   the env shows whether the flag is set.
6. **The database.** `pg_policies` and table grants for the anon and authenticated roles. Any
   policy that lets the public key insert into a table the app trusts, any table with row security
   off. Check whether the public key ever reaches a browser before calling it urgent.
7. **History.** Scan every revision for key formats (`git rev-list --all | xargs -n 200 git grep
   -IhoE '<patterns>'`), at least Anthropic, Stripe, Supabase secret, AWS, GitHub, Slack, Resend,
   Google, SendGrid, private keys and database URLs with passwords. Report a hit only after reading
   it: local-dev defaults and test fixtures are common.
8. **Dependencies.** `npm audit --omit=dev`.
9. **Fix, then prove it.** Tests for anything with logic (limits, budgets, gates). Run the built
   server locally and check headers, the cross-site guard, and that a limit holds while the
   forwarded address rotates. Then commit with a message that says what was open and why it
   mattered.

## What the first sweep found

The fleet audit on Oct 22–23 2026, so the next one knows what to look for:

| Pattern | Where it turned up |
| --- | --- |
| Reply email quoting the sender to an unverified address | unakin.com intake (the botnet's whole motive) |
| Mail relay with per-user limits but no site-wide ceiling | Spacelab Studio (any Google account) |
| Scheduled sends skipping the immediate send's gates | Spacelab Studio |
| Admin page open because no key was configured | Panogram |
| Leftmost `X-Forwarded-For` behind the rate limiter | Shotgun Detour |
| HSTS never sent behind the proxy | portal.unakin.com |
| No headers at all | Shotgun Detour, Panogram, unakin.com/play |
| Locked assets decrypted without the cookie | davidpuerto.com |
| Alert emails anyone could trigger without limit | davidpuerto.com visit log |
| Public routes passing any radius to a free public API | Shotgun Detour, Panogram |
| Form showing success while saving nowhere | spacelabforever.com waitlist |

What held, and is worth copying: unakin.com's layered intake gates and forensic log,
portal.unakin.com's enforcing CSP with no inline scripts, Sedulous's hashed-script CSP, the comms
relay's secret checked at two layers, and Shipmate's OAuth 2.1 with passkeys.

## Tests

`assets/shield.test.mjs` covers the module: `node --test assets/shield.test.mjs`.
