---
name: site-hardening
description: The security baseline every website and web app gets from its first commit, the live check that catches drift, and the audit for an existing site. Drops in shield.mjs (real client address, security headers, cross-site guard, per-address plus site-wide rate limits, spending budgets and AI tiers, fail-closed key gates, form gates against bots, forensic log, spike alerts, the no-relay email rule) plus a fleet-wide blocklist, for Astro, Express, Next.js or plain Node. Use when starting any new site or app, adding a form, an email send, an admin page, an AI call or a public API route, when a form is being hammered, or when the user says "harden this", "security review", "are we safe from bots", "audit the site", "check the sites", "lock this down". Fleet tool, works from any project directory.
---

# /site-hardening

Every site starts with this, and every live site gets checked by it. It came out of one night in
October 2026: a botnet spent a month trying to turn the unakin.com contact form into a mail relay,
and the sweep that followed found the same handful of holes across the fleet. None were exotic.
They were defaults nobody revisited, and two of the worst were invisible in code.

Three modes. **New site**: install the baseline before the first deploy. **Check**: run
`check.mjs` against a live domain, on a schedule. **Audit**: walk an existing site through the
steps below and fix what fails. Do the work, test it, commit; push only when the user says to,
because a push to main deploys.

## Assets

| File | What it is |
| --- | --- |
| `assets/shield.mjs` | The module. No dependencies. Every export is short enough to read first. |
| `assets/adapters.md` | Wiring for Astro, static hosts, Express, Next.js, plain Node, Supabase, and the sentinel. |
| `assets/check.mjs` | The live check: headers, cross-site guard, forged-address limits, dependencies, mail records, embeds. |
| `assets/blocklist.mjs` | One blocklist for the whole fleet, refreshed from a shared URL, seeded with the known-bad ranges. |
| `assets/attempts.sql` | The forensic log table, row security, 30-day retention, and the queries you ask it. |
| `assets/supabase-audit.sql` | Five queries that find loose policies, missing row security and open functions. |
| `assets/csp.md` | Content Security Policy in three steps: report only, move inline code out, enforce. |
| `assets/incident.md` | The runbook for a form under attack: what's getting through, remove the payoff, characterize, block, report. |
| `assets/shield.test.mjs` | `node --test assets/shield.test.mjs` |

## The baseline

Copy `shield.mjs` (and `blocklist.mjs`) into the project, wire it per `adapters.md`, then:

1. **Real client address.** `clientIp(req)` reads the edge's own header (`do-connecting-ip`,
   `cf-connecting-ip`), never the leftmost `X-Forwarded-For`, which the visitor writes. Every rate
   limit keys on this.
2. **Security headers** on every response: HSTS, nosniff, frame policy, referrer policy, a
   permissions policy that allows only what the site uses. Read the protocol from
   `x-forwarded-proto`: behind a proxy the app's own URL always says http, and HSTS silently never
   ships. Drop `X-Powered-By`. Then the CSP, by the procedure in `csp.md`.
3. **Cross-site guard.** `crossSiteRefused(req)` on every state-changing request. Framework origin
   checks often misread the host behind a proxy and get switched off; this one compares against
   `x-forwarded-host` too.
4. **Two rate limits on every public write**: per address and site-wide. A botnet rotating addresses
   walks past per-address limits; the site-wide one is the ceiling.
5. **Budgets on anything that spends.** Outgoing mail through your own account, paid models,
   third-party APIs that can ban your server: `budget(cap, DAY)`, shared across every user. Paid
   models go through `tierBudget`: the server owns the model map, each tier has its own daily cap,
   a spent tier falls back to the default, and `onWarn` fires at 80 percent.
6. **The shared blocklist.** `new Blocklist({ url: BLOCKLIST_URL })` in every app, one JSON file
   behind that URL. A range that attacked one site is blocked on all of them within the hour.
7. **Gates that fail closed.** `keyGate(given, process.env.ADMIN_KEY)`: no key configured in
   production means nobody gets in, not everybody.
8. **Form gates**, cheapest first: blocklist, honeypot, signed render token with a 4-second minimum
   (`formToken`), `requestLooksForged`, `looksLikeBot`, then the rate limits. Answer every drop with
   the normal success response so a bot learns nothing.
9. **A forensic log and a spike alert on every form.** `attemptRow` writes one row per hit to the
   `attempts` table, accepted or dropped, with the header fingerprint and the typed address hashed.
   `spikeAlert` tells the owner within the hour when drops or accepts jump, then stays silent for
   six hours. The log is how an attack becomes an abuse report.
10. **The relay rule.** Mail to an address someone typed goes to a stranger until it's verified, so
    it carries nothing they wrote: no name, no quote, no subject from the form. Where a list
    sign-up mails anyone, make it double opt-in, and make the confirm link open a page whose
    *button* confirms: mail scanners (Outlook Safe Links, corporate gateways) open every link in a
    message, so a link that confirms on a visit confirms every bot-submitted address.
11. **Gated content stays gated.** Every asset a protected page loads checks the same cookie as the
    page, especially when a public repo lists the asset names.
12. **Secrets out of git**, the secret key out of every browser bundle, row security on every
    table, and no public insert policy on a table something else trusts (`supabase-audit.sql`).
13. **Mail reputation.** Every sending domain has SPF, DKIM and a DMARC policy of quarantine or
    reject. `p=none` only monitors; `check.mjs --mail` flags it.
14. **Privacy defaults.** Honor Do Not Track and Global Privacy Control on any visit log. Keep
    addresses 365 days at most on analytics, 30 days on attempt logs, and hash a typed email
    rather than store it. Say so on the privacy page.

## The live check

```
node ~/.claude/skills/site-hardening/assets/check.mjs https://example.com \
  --form /api/contact --resolve <project>.supabase.co --mail example.com --embed /embed
```

Run it after every deploy and on a schedule. It found, from outside, the HSTS header one app
believed it was sending and a waitlist posting to a database project that no longer existed.
`--limits N` proves a forged address can't escape the per-address cap, but it spends N hits of
the form's real caps, so run it right after a deploy, not every five minutes. `--json` gives a
sentinel something to diff; `adapters.md` shows the Shipmate hookup.

## The audit

Work one site at a time, and record each in the hardening log if the user keeps one.

1. **What's live.** Map repos to deployments (`doctl apps list`, the app spec's components and
   domains). Note the stack and whether the repo is public.
2. **From outside.** `check.mjs` on every domain. Missing HSTS on an app that "sets" it means the
   protocol check is wrong. A missing dependency means a form is failing silently.
3. **Every route.** List API routes and, for each: who may call it, what it writes, what it spends,
   what it sends, what it calls outside. Look hardest at routes that are public AND write, send or
   spend. Scheduled jobs that send go through the same gates as the immediate path.
4. **The usual suspects.** Grep for `x-forwarded-for` (leftmost read), `checkOrigin: false` or
   origin checks against `Host`, `if (KEY && ...)` gates, `=== secret` comparisons, `sendMail` or
   provider sends to a user-supplied address, user text inside outgoing mail, model choice taken
   from the request, unbounded query parameters passed to third-party APIs, provider error text
   returned to the browser, in-memory maps with no size bound.
5. **Settings beat comments.** Read the live environment (`doctl apps spec get <id> --format json`,
   keys only, never print secret values). A comment saying "disabled in production" is a claim;
   the env shows whether the flag is set.
6. **The database.** `supabase-audit.sql` on every project. Any policy that lets the public key
   write a table the app trusts, any table with row security off, any view without
   `security_invoker`. Check whether the public key reaches a browser before calling it urgent.
7. **History.** Scan every revision for key formats (`git rev-list --all | xargs -n 200 git grep
   -IhoE '<patterns>'`), at least Anthropic, Stripe, Supabase secret, AWS, GitHub, Slack, Resend,
   Google, SendGrid, private keys and database URLs with passwords. Report a hit only after reading
   it: local-dev defaults and test fixtures are common.
8. **Dependencies.** `npm audit --omit=dev`, and Dependabot on the repo.
9. **Fix, then prove it.** Tests for anything with logic (limits, budgets, gates). Run the built
   server locally and check headers, the cross-site guard, and that a limit holds while the
   forwarded address rotates. Then commit with a message that says what was open and why it
   mattered.

## Under attack right now

Open `assets/incident.md` and work it top to bottom. The order matters: find out what's getting
through, remove the payoff, then characterize, block and report. Nothing goes back toward the
addresses; they're rented machines.

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
| Form showing success while saving to a dead database | spacelabforever.com waitlist |
| DMARC left at monitor-only on a sending domain | davidpuerto.com, spacelabforever.com |
| Waitlist written straight from the browser, welcome mailed on insert: a subscription-bombing bot's payoff (15 strangers signed up in a day, 2026-10-28) | spacelabforever.com (fixed 2026-10-29: edge function behind the gates, double opt-in) |
| New tables invisible to the function's own role (Supabase auto-expose off): the hardened form 502'd every real sign-up and logged nothing, while bots still saw `{ok:true}` | spacelabforever.com: grant `service_role` explicitly; prove it with one real sign-up, not only bot probes |
| A new page's inline script silently blocked by the site's own CSP (`script-src 'self'`): the confirm button did nothing | spacelabforever.com confirm page: scripts go in their own file |
| "Authenticated" read policies with `using (true)`: any signed-in account reads every row | spacelabforever.com waitlist and events |

What held, and is worth copying: unakin.com's layered intake gates and forensic log,
portal.unakin.com's enforcing CSP with no inline scripts, Sedulous's hashed-script CSP, the comms
relay's secret checked at two layers, and Shipmate's OAuth 2.1 with passkeys.
