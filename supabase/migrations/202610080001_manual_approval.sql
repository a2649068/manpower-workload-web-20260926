-- Transactional and repeatable. Run audit.sql first; use a staging project first.
begin;
create schema if not exists approval_private;
revoke all on schema approval_private from public, anon, authenticated;
create table if not exists public.approval_admins (
  user_id uuid primary key references auth.users(id) on delete cascade
);
create table if not exists public.approved_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  approved_at timestamptz not null default now(),
  approved_by uuid references auth.users(id) on delete set null
);
alter table public.approval_admins enable row level security;
alter table public.approved_users enable row level security;
revoke all on public.approval_admins, public.approved_users from public, anon, authenticated;
-- No client table policies: access only through checked RPCs. No metadata/JWT admin flags.
create or replace function approval_private.is_admin() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists(select 1 from public.approval_admins a join auth.users u on u.id=a.user_id
    where a.user_id=auth.uid() and u.email_confirmed_at is not null)
$$;
create or replace function public.has_approved_access() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists(select 1 from public.approved_users a join auth.users u on u.id=a.user_id
    where a.user_id=auth.uid() and u.email_confirmed_at is not null)
$$;
create or replace function public.my_access_status() returns jsonb
language sql stable security definer set search_path = '' as $$
  select jsonb_build_object('approved',public.has_approved_access(),
    'admin',approval_private.is_admin())
$$;
create or replace function public.admin_list_users()
returns table(user_id uuid,email text,registered_at timestamptz,verified_at timestamptz,
  approved_at timestamptz,is_admin boolean)
language plpgsql security definer set search_path = '' as $$
begin
  if not approval_private.is_admin() then raise exception 'Administrator required' using errcode='42501'; end if;
  return query select u.id,u.email::text,u.created_at,u.email_confirmed_at,a.approved_at,
    exists(select 1 from public.approval_admins m where m.user_id=u.id)
    from auth.users u left join public.approved_users a on a.user_id=u.id order by u.created_at desc;
end $$;
create or replace function public.admin_set_approval(p_user_id uuid,p_approved boolean)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not approval_private.is_admin() then raise exception 'Administrator required' using errcode='42501'; end if;
  if p_approved is null then raise exception 'Approval required' using errcode='22023'; end if;
  -- Lock target Auth row so approval and deletion/verification do not race.
  perform 1 from auth.users where id=p_user_id for update;
  if not found then raise exception 'User not found' using errcode='22023'; end if;
  if p_approved then
    if not exists(select 1 from auth.users where id=p_user_id and email_confirmed_at is not null)
      then raise exception 'Email must be verified first' using errcode='22023'; end if;
    insert into public.approved_users(user_id,approved_by) values(p_user_id,auth.uid())
      on conflict(user_id) do nothing;
  else
    delete from public.approved_users where user_id=p_user_id;
  end if;
end $$;
revoke all on function approval_private.is_admin() from public,anon,authenticated;
revoke all on function public.has_approved_access(),public.my_access_status(),
 public.admin_list_users(),public.admin_set_approval(uuid,boolean) from public,anon,authenticated;
grant execute on function public.has_approved_access(),public.my_access_status(),
 public.admin_list_users(),public.admin_set_approval(uuid,boolean) to authenticated;

-- RESTRICTIVE gates cannot be bypassed by an existing permissive USING(true) policy.
-- Keep existing policies and privileges; seed a permissive policy only if none exists.
do $block$
declare t text;
begin
  foreach t in array array['assignments','summary_people'] loop
    if to_regclass('public.'||t) is null then raise exception 'Missing formal table: %',t; end if;
    execute format('alter table public.%I enable row level security',t);
    execute format('drop policy if exists approval_required on public.%I',t);
    execute format('create policy approval_required on public.%I as restrictive for all to public using ((select public.has_approved_access())) with check ((select public.has_approved_access()))',t);
    if not exists(select 1 from pg_policies where schemaname='public' and tablename=t and permissive='PERMISSIVE') then
      execute format('create policy approved_baseline on public.%I for all to authenticated using ((select public.has_approved_access())) with check ((select public.has_approved_access()))',t);
    end if;
    revoke execute on function public.has_approved_access() from anon;
    -- Anonymous clients must never read or mutate formal data, including TRUNCATE.
    execute format('revoke all on public.%I from public,anon',t);
    execute format('revoke truncate,references,trigger on public.%I from authenticated',t);
  end loop;
end $block$;

-- Publish only a harmless invalidation counter, never formal row payloads/DELETE keys.
-- This preserves live refresh while closing Postgres Changes' DELETE RLS exception.
create table if not exists public.manpower_changes (
  id integer primary key check(id=1), revision bigint not null default 0
);
insert into public.manpower_changes(id) values(1) on conflict do nothing;
alter table public.manpower_changes enable row level security;
revoke all on public.manpower_changes from public,anon,authenticated;
grant select on public.manpower_changes to authenticated;
drop policy if exists approved_refresh on public.manpower_changes;
create policy approved_refresh on public.manpower_changes for select to authenticated
  using ((select public.has_approved_access()));
create or replace function approval_private.notify_manpower_change() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  update public.manpower_changes set revision=revision+1 where id=1;
  return null;
end $$;
revoke all on function approval_private.notify_manpower_change() from public,anon,authenticated;
drop trigger if exists approval_refresh on public.assignments;
create trigger approval_refresh after insert or update or delete on public.assignments
  for each statement execute function approval_private.notify_manpower_change();
drop trigger if exists approval_refresh on public.summary_people;
create trigger approval_refresh after insert or update or delete on public.summary_people
  for each statement execute function approval_private.notify_manpower_change();
do $block$
declare t text;
begin
  if not exists(select 1 from pg_publication where pubname='supabase_realtime') then
    create publication supabase_realtime;
  end if;
  if exists(select 1 from pg_publication where pubname='supabase_realtime' and puballtables) then
    raise exception 'Review FOR ALL TABLES publication before deploying approval';
  end if;
  foreach t in array array['assignments','summary_people'] loop
    if exists(select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename=t) then
      execute format('alter publication supabase_realtime drop table public.%I',t);
    end if;
  end loop;
  if not exists(select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='manpower_changes') then
    alter publication supabase_realtime add table public.manpower_changes;
  end if;
end $block$;

-- Preserve original RPC implementations/signatures; move them outside exposed public.
-- Checked wrappers are essential because an original SECURITY DEFINER can bypass RLS.
do $block$
declare r record; args text; result_type text; invocation text; body text; n text;
begin
  foreach n in array array['set_assignment_cell','delete_assignment_row','set_summary_person'] loop
    if not exists(select 1 from pg_proc p join pg_namespace s on s.oid=p.pronamespace
      where s.nspname='approval_private' and p.proname=n) then
      if not exists(select 1 from pg_proc p join pg_namespace s on s.oid=p.pronamespace
        where s.nspname='public' and p.proname=n) then raise exception 'Missing original RPC: %',n; end if;
      for r in select p.* from pg_proc p join pg_namespace s on s.oid=p.pronamespace
        where s.nspname='public' and p.proname=n loop
        if r.prokind<>'f' or r.proargmodes is not null or r.proargnames is null then
          raise exception 'Review unsupported RPC signature: %',r.oid::regprocedure;
        end if;
        execute format('alter function public.%I(%s) set schema approval_private',n,pg_get_function_identity_arguments(r.oid));
      end loop;
    end if;
    for r in select p.* from pg_proc p join pg_namespace s on s.oid=p.pronamespace
      where s.nspname='approval_private' and p.proname=n loop
      -- The wrapper has an empty search_path; keep old unqualified table references working.
      if not exists(select 1 from unnest(r.proconfig) c where c like 'search_path=%') then
        execute format('alter function approval_private.%I(%s) set search_path = pg_catalog, public, pg_temp',n,pg_get_function_identity_arguments(r.oid));
      end if;
      args:=pg_get_function_arguments(r.oid);
      result_type:=pg_get_function_result(r.oid);
      select string_agg(format('%I',a),',') into invocation from unnest(r.proargnames) a;
      invocation:=format('approval_private.%I(%s)',n,coalesce(invocation,''));
      if r.proretset then body:='return query select * from '||invocation||';';
      elsif r.prorettype='void'::regtype then body:='perform '||invocation||'; return;';
      else body:='return '||invocation||';'; end if;
      execute format('create or replace function public.%I(%s) returns %s language plpgsql security definer set search_path = '''' as %L',n,args,result_type,
        'begin if not public.has_approved_access() then raise exception ''Approval required'' using errcode=''42501''; end if; '||body||' end');
      execute format('revoke all on function approval_private.%I(%s) from public,anon,authenticated',n,pg_get_function_identity_arguments(r.oid));
      execute format('revoke all on function public.%I(%s) from public,anon,authenticated',n,pg_get_function_identity_arguments(r.oid));
      execute format('grant execute on function public.%I(%s) to authenticated',n,pg_get_function_identity_arguments(r.oid));
    end loop;
  end loop;
end $block$;
notify pgrst,'reload schema';
commit;
-- No existing business rows or Auth users are changed. Realtime publishes invalidations only.
-- Bootstrap an explicitly selected VERIFIED administrator using docs/APPROVAL_SETUP.md.
