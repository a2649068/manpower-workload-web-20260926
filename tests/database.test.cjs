const {test}=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const path=require('node:path');
const {PGlite}=require(process.env.PGLITE_PATH||'@electric-sql/pglite');
const ids={admin:'00000000-0000-0000-0000-000000000001',pending:'00000000-0000-0000-0000-000000000002',unverified:'00000000-0000-0000-0000-000000000003'};
test('transactional migration, live RLS and definer RPC authorization',async()=>{
 const db=new PGlite();
 try{
 await db.exec(`create role anon;create role authenticated;create role service_role bypassrls;create schema auth;
 create table auth.users(id uuid primary key,email text,created_at timestamptz default now(),email_confirmed_at timestamptz);
 create function auth.uid() returns uuid language sql stable as $$select nullif(current_setting('request.jwt.claim.sub',true),'')::uuid$$;
 grant usage on schema public,auth to anon,authenticated;grant execute on function auth.uid() to anon,authenticated;
 create table public.assignments(row_index int primary key,person_name text,project_name text,start_date date,end_date date);
 create table public.summary_people(slot int primary key,person_name text);
 insert into assignments values(2,'original',null,null,null);insert into summary_people values(1,'original');
 alter table assignments enable row level security;alter table summary_people enable row level security;
 create policy old_open on assignments for all to public using(true) with check(true);
 create policy old_open on summary_people for all to public using(true) with check(true);
 grant all on assignments,summary_people to anon,authenticated;
 create function public.set_assignment_cell(p_row_index int,p_field text,p_value text) returns void language plpgsql security definer as $$begin update assignments set person_name=p_value where row_index=p_row_index;end$$;
 create function public.delete_assignment_row(p_row_index int) returns void language plpgsql security definer as $$begin delete from assignments where row_index=p_row_index;end$$;
 create function public.set_summary_person(p_slot int,p_person text) returns void language plpgsql security definer as $$begin update summary_people set person_name=p_person where slot=p_slot;end$$;
 insert into auth.users(id,email,email_confirmed_at) values('${ids.admin}','admin@test',now()),('${ids.pending}','pending@test',now()),('${ids.unverified}','unverified@test',null);`);
 const sql=fs.readFileSync(path.join(__dirname,'../supabase/migrations/202610080001_manual_approval.sql'),'utf8');
 await db.exec(sql);await db.exec(sql); // Repeatability, data preservation.
 assert.equal((await db.query('select person_name from assignments')).rows[0].person_name,'original');
 await db.exec(`insert into approval_admins values('${ids.admin}');insert into approved_users(user_id) values('${ids.admin}');`);
 async function asUser(id,query,role='authenticated'){
  await db.exec(`begin;set local role ${role};select set_config('request.jwt.claim.sub','${id||''}',true);`);
  try{return await db.query(query)}finally{await db.exec('rollback')}
 }
 assert.equal((await asUser(ids.pending,'select * from assignments')).rows.length,0);
 assert.equal((await asUser(ids.pending,'select * from manpower_changes')).rows.length,0);
 for(const query of ["select set_assignment_cell(2,'name','intrusion')","select delete_assignment_row(2)","select set_summary_person(1,'intrusion')","select admin_list_users()",`select admin_set_approval('${ids.pending}',true)`]){
  await assert.rejects(asUser(ids.pending,query),e=>e.code==='42501');
 }
 await assert.rejects(asUser(null,'select * from assignments','anon'));
 await assert.rejects(asUser(ids.pending,"insert into assignments(row_index) values(9)"));
 assert.equal((await asUser(ids.pending,"update assignments set person_name='intrusion' returning *")).rows.length,0);
 assert.equal((await asUser(ids.pending,'delete from assignments returning *')).rows.length,0);
 await assert.rejects(asUser(ids.pending,'truncate assignments'));
 await assert.rejects(asUser(ids.pending,`insert into approved_users(user_id) values('${ids.pending}')`));
 await assert.rejects(asUser(ids.pending,"select approval_private.set_assignment_cell(2,'name','intrusion')"));
 assert.equal((await asUser(ids.admin,'select * from admin_list_users()')).rows.length,3);
 await assert.rejects(asUser(ids.admin,`select admin_set_approval('${ids.unverified}',true)`));
 // Commit admin approval, then reuse same UID/JWT after revoke.
 await db.exec(`begin;set local role authenticated;select set_config('request.jwt.claim.sub','${ids.admin}',true);select admin_set_approval('${ids.pending}',true);commit;`);
 assert.equal((await asUser(ids.pending,'select * from assignments')).rows.length,1);
 assert.deepEqual((await db.query("select tablename from pg_publication_tables where pubname='supabase_realtime'")).rows.map(r=>r.tablename),['manpower_changes']);
 await asUser(ids.pending,"select set_assignment_cell(2,'name','allowed')");
 await asUser(ids.pending,"select set_summary_person(1,'allowed')");
 await asUser(ids.pending,'select delete_assignment_row(2)');
 await db.exec(`begin;set local role authenticated;select set_config('request.jwt.claim.sub','${ids.admin}',true);select admin_set_approval('${ids.pending}',false);commit;`);
 assert.equal((await asUser(ids.pending,'select * from assignments')).rows.length,0);
 await assert.rejects(asUser(ids.pending,"select set_assignment_cell(2,'name','revoked')"));
 // Verification is read from auth.users, not a possibly stale JWT claim.
 await db.exec(`insert into approved_users(user_id) values('${ids.unverified}');`);
 assert.equal((await asUser(ids.unverified,'select has_approved_access() as ok')).rows[0].ok,false);
 assert.equal((await db.query('select person_name from assignments')).rows[0].person_name,'original');
 }finally{await db.close()}
});
