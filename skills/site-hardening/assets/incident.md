# Incident runbook: a form is being hammered

What took a night on Oct 22–23 2026, written down so it takes an hour. Work top to bottom.

## 1. Is anything getting through?

```sql
select date_trunc('day', created_at)::date, reason, count(*), count(distinct ip)
from attempts where created_at > now() - interval '7 days' group by 1,2 order by 1 desc, 3 desc;
```

`accepted` rows are the only emergency. Everything else is noise the gates are already eating.
Check the thing the bot wants (a leads table, a sent-mail log, a credit balance) for the same window.

## 2. Remove the payoff

Ask what the bot gets if it wins. A reply email that quotes its text to an address it typed: strip
the quote. A relay with per-user limits: add the site-wide budget. A counter it can inflate: limit
it. A bot with nothing to win moves on; a block alone just makes it rotate addresses.

## 3. Characterize it

```sql
select regexp_replace(host(ip), '\.\d+$', '') net, count(*), count(distinct victim_domain),
       min(created_at), max(created_at), max(ua), bool_or((shape->>'honeypot')::bool), avg(token_age_s)
from attempts where created_at > now() - interval '7 days' and reason <> 'accepted'
group by 1 order by 2 desc limit 20;
```

Then for the top ranges:

```sh
whois -h whois.ripe.net <ip> | grep -E "^(inetnum|netname|org-name|country|abuse-mailbox|origin|mnt-by|remarks)"
curl -s "https://stat.ripe.net/data/routing-status/data.json?resource=<cidr>" | jq '.data.origins, .data.first_seen'
curl -s "https://stat.ripe.net/data/geoloc/data.json?resource=<cidr>" | jq '.data.located_resources[0].locations[0]'
curl -s "https://stat.ripe.net/data/as-overview/data.json?resource=AS<n>" | jq '.data.holder'
```

Placeholder org names, "Private Customer" roles, a lease marketplace in the maintainer, and a
geofeed pointing at a data-center city mean rented proxy space. The operator is not there.

## 4. Block the ranges everywhere

Add the CIDRs to the shared blocklist (see `blocklist.mjs`): every site picks them up within the
hour. Add a dated comment. Don't block a residential ISP's whole range on one bad address.

## 5. Report it

Build the evidence file from the log (UTC time, address, reason, user agent) and send one email to:

- the `abuse-mailbox` on the RIPE/ARIN record,
- the maintainer's support address if the owner's name is withheld, quoting their reference,
- the upstream's abuse desk (`abuse@` of the AS holder).

Say what the traffic is, how many addresses, what it targets, that nothing was delivered, and
attach the file. Reporting every dropped address to AbuseIPDB (the portal has a key) raises
their scores for everyone else too.

## 6. Watch the new ranges

The operator will add ranges. The forged-header checks caught the two new ones in October
before the blocklist knew them. Re-run step 3 weekly for a month, then prune the blocklist
comments when a range has been quiet for 90 days.

## What not to do

Nothing goes back toward the addresses. They are rented machines in someone's data center, and
the only lawful levers are the leasing company, the upstream, and the police. Frankfurt's
prosecutors have a central internet-crime office if it ever rises to that.
