# site-hardening

The security baseline every site and app gets from its first commit, the live check that catches
drift, and the audit for an existing site. A Claude Code skill plus dependency-free modules. It
came out of the October 2026 fleet sweep that followed a month-long botnet run at a contact form.

- `skills/site-hardening/SKILL.md`: the 14-point baseline, the live check, the audit, and what the first sweep found.
- `assets/shield.mjs`: client address, headers, cross-site guard, rate limits, budgets and AI tiers,
  fail-closed key gates, form gates, forensic log rows, spike alerts, the no-relay rule.
- `assets/check.mjs`: run against a live domain; exits 1 on drift.
- `assets/blocklist.mjs`: one fleet-wide blocklist from a shared URL.
- `assets/attempts.sql`, `assets/supabase-audit.sql`: the log table and the database audit.
- `assets/adapters.md`, `assets/csp.md`, `assets/incident.md`: wiring, the CSP procedure, the runbook.

Install: `ln -s "$PWD/skills/site-hardening" ~/.claude/skills/site-hardening`

Test: `node --test skills/site-hardening/assets/shield.test.mjs`

Check a site: `node skills/site-hardening/assets/check.mjs https://example.com --form /api/contact --mail example.com`
