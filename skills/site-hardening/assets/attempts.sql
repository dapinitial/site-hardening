-- attempts.sql — the forensic log every public form gets.
--
-- One row per hit, accepted or dropped, with why. This is what made the 2026-09/10 botnet
-- legible: the header fingerprint showed headless Chromium behind a 2005 user agent, the
-- timing showed it loading the page, and the target domains filled the abuse report.
-- The server writes it with the secret key; nothing public can read or write it.
-- Rows expire after 30 days (pg_cron), the same window the abuse desks ask about.
-- The address the sender typed is stored as a keyed hash plus its domain, never in clear.

create table if not exists public.attempts (
  id            bigint generated always as identity primary key,
  created_at    timestamptz not null default now(),
  site          text not null,                  -- 'unakin.com', 'davidpuerto.com' …
  form          text not null,                  -- '/api/intake', '/api/contact' …
  reason        text not null,                  -- 'accepted' or the gate that dropped it
  ip            inet,
  ip_diag       text,                           -- every address-bearing header, for the proxy chain
  ua            text,
  headers       jsonb,                          -- a fixed allowlist of request headers
  header_order  text[],                         -- header order is a cheap client fingerprint
  token_age_s   numeric,                        -- seconds between page render and submit
  pow           text,                           -- 'off' | 'ok' | 'missing' | 'weak'
  shape         jsonb,                          -- field lengths, word counts, honeypot, flags
  victim_hash   text,                           -- HMAC of the typed address
  victim_domain text
);
create index if not exists attempts_created_idx on public.attempts (created_at desc);
create index if not exists attempts_site_reason_idx on public.attempts (site, reason, created_at desc);

alter table public.attempts enable row level security;
-- no policies: anon and authenticated get nothing; the service role bypasses RLS.
revoke all on public.attempts from anon, authenticated;

-- retention: 30 days (pg_cron must be enabled on the project)
select cron.schedule('attempts-retention', '17 3 * * *', $$delete from public.attempts where created_at < now() - interval '30 days'$$)
  where not exists (select 1 from cron.job where jobname = 'attempts-retention');

-- the questions you ask it
-- who's hitting us, by /24, this week:
--   select regexp_replace(host(ip), '\.\d+$', '') net, reason, count(*), count(distinct victim_domain)
--   from attempts where created_at > now() - interval '7 days' group by 1,2 order by 3 desc;
-- did anything get through:
--   select date_trunc('day', created_at), count(*) from attempts where reason = 'accepted' group by 1;
-- evidence for an abuse report:
--   select to_char(created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'), host(ip), reason, ua
--   from attempts where reason <> 'accepted' and created_at > now() - interval '30 days' order by 1;
