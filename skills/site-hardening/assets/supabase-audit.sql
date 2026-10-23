-- supabase-audit.sql — run against each project (SQL editor or the MCP execute_sql tool).
-- Read the results against one rule: the public key never writes a table something else trusts,
-- and never reads a table with personal data.

-- 1. every table: row security on? how many policies? what can the public roles do?
select c.relname as "table", c.relrowsecurity as rls,
       (select count(*) from pg_policies p where p.schemaname = 'public' and p.tablename = c.relname) as policies,
       has_table_privilege('anon', c.oid, 'select') as anon_select,
       has_table_privilege('anon', c.oid, 'insert') as anon_insert,
       has_table_privilege('anon', c.oid, 'update') as anon_update,
       has_table_privilege('authenticated', c.oid, 'update') as auth_update
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relkind = 'r' order by 1;
-- red flags: rls = false on any table; rls = true with policies = 0 is fine (nothing gets in).

-- 2. every policy that lets anon or public write
select tablename, policyname, cmd, roles::text, qual, with_check
from pg_policies
where schemaname = 'public' and cmd in ('INSERT', 'UPDATE', 'DELETE', 'ALL')
  and (roles::text like '%anon%' or roles::text like '%public%')
order by tablename, cmd;
-- each row is a table the browser key can change. For each: is that table trusted by anything
-- (a leads queue, a log, a waitlist, a counter)? If so, move the write to the server.

-- 3. security-definer functions (they run as their owner; a loose one is a back door)
select p.proname, pg_get_function_arguments(p.oid) args, p.prosecdef as security_definer,
       (select string_agg(x, ', ') from unnest(p.proconfig) x) as config
from pg_proc p join pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public' and p.prosecdef order by 1;
-- each should set search_path and be callable only by who needs it:
--   revoke execute on function public.f() from anon, public;

-- 4. views and tables exposed through the API without RLS behind them
select table_name, table_type from information_schema.tables
where table_schema = 'public' and table_type = 'VIEW';
-- a view bypasses the base tables' RLS unless created with security_invoker = true.

-- 5. retention jobs exist for anything holding addresses
select jobname, schedule, command from cron.job order by 1;
