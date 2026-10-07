-- Read-only. Run in the project's SQL Editor BEFORE the migration and save results privately.
select current_database(), current_user, version();
select n.nspname, c.relname, c.relkind, c.relrowsecurity, c.relforcerowsecurity
from pg_class c join pg_namespace n on n.oid=c.relnamespace
where n.nspname='public' and c.relkind in ('r','p','v','m') order by 1,2;
select * from pg_policies where schemaname in ('public','realtime') order by tablename,policyname;
select * from information_schema.role_table_grants where table_schema='public'
  and grantee in ('PUBLIC','anon','authenticated','service_role');
select p.oid::regprocedure as function, p.prosecdef as security_definer,
  p.proconfig, p.proacl, pg_get_functiondef(p.oid) as definition
from pg_proc p join pg_namespace n on n.oid=p.pronamespace
where n.nspname='public' and p.prokind='f' order by 1;
select pubname,schemaname,tablename from pg_publication_tables order by pubname,schemaname,tablename;
select count(*) as registered, count(email_confirmed_at) as verified from auth.users;
-- Dashboard: separately confirm email confirmation ON, exposed schemas, Edge Function
-- sheet-reference source/auth, Storage policies, and any other API accessing formal data.
