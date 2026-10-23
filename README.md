# site-hardening

The security baseline every site and app gets from its first commit, as a Claude Code skill plus
one dependency-free module, `shield.mjs`. It came out of the October 2026 fleet sweep that followed
a month-long botnet run at the unakin.com contact form.

- `skills/site-hardening/SKILL.md`: the baseline, the audit procedure, and what the first sweep found.
- `skills/site-hardening/assets/shield.mjs`: client address, headers, cross-site guard, rate limits,
  budgets, fail-closed key gates, form gates, the no-relay rule.
- `skills/site-hardening/assets/adapters.md`: wiring for Astro, Express, Next.js and plain Node.

Install: `ln -s "$PWD/skills/site-hardening" ~/.claude/skills/site-hardening`

Test: `node --test skills/site-hardening/assets/shield.test.mjs`
