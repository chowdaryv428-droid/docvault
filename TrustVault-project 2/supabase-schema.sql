-- =====================================================================
-- TrustVault on Supabase
-- Run this whole file once in the Supabase SQL editor (Dashboard > SQL).
--
-- Design: browsers never touch the tables. Every table has Row Level
-- Security switched on with NO policies, so direct reads/writes are
-- impossible. All access goes through the tv_* functions below, which
-- re-check account status, role and document grant on every call and
-- write the hash-chained audit log (including refused attempts).
-- Files live in a private Storage bucket whose policies call back into
-- the same rules.
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------- clean start (safe: removes only TrustVault's own objects) ---
-- Your own existing "profiles" table (if any) is never touched; TrustVault uses tv_profiles.
drop policy if exists "vault insert" on storage.objects;
drop policy if exists "vault select" on storage.objects;
drop policy if exists "vault delete" on storage.objects;
drop trigger if exists on_auth_user_created on auth.users;
do $$
declare r record;
begin
  for r in select p.oid::regprocedure as sig
             from pg_proc p join pg_namespace n on n.oid = p.pronamespace
            where n.nspname = 'public' and p.proname like 'tv%' loop
    execute format('drop function if exists %s cascade', r.sig);
  end loop;
end $$;
drop table if exists public.storage_purge, public.doc_grants, public.documents, public.audit_log, public.tv_profiles cascade;

-- ---------- tables ----------------------------------------------------
create table if not exists public.tv_profiles (
  id         uuid primary key references auth.users(id) on delete cascade,
  username   text not null unique check (username ~ '^[a-z0-9_.-]{3,30}$'),
  name       text not null check (char_length(name) between 2 and 60),
  role       text not null check (role in ('admin','owner','viewer')),
  active     boolean not null default true,
  approved   boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists public.documents (
  id           uuid primary key default gen_random_uuid(),
  name         text not null,
  ext          text not null,
  category     text not null,
  owner_id     uuid not null references public.tv_profiles(id),
  size         integer not null,
  created_at   timestamptz not null default now(),
  modified_at  timestamptz,
  version      integer not null default 1,
  visibility   text not null check (visibility in ('everyone','private')),
  storage_path text not null unique
);

create table if not exists public.doc_grants (
  doc_id  uuid not null references public.documents(id) on delete cascade,
  user_id uuid not null references public.tv_profiles(id) on delete cascade,
  perm    text not null check (perm in ('read','edit')),
  primary key (doc_id, user_id)
);

create table if not exists public.audit_log (
  seq        bigint primary key,
  ts         timestamptz not null,
  actor      uuid,
  actor_name text,
  action     text not null,
  doc_id     uuid,
  doc_name   text,
  outcome    text not null,
  detail     text not null default '',
  prev       text not null,
  hash       text not null
);
create index if not exists audit_actor_doc_ts on public.audit_log (actor, doc_id, ts desc);
create index if not exists audit_doc on public.audit_log (doc_id);

-- files that a user is allowed to remove from Storage after a delete / content change
create table if not exists public.storage_purge (
  path         text primary key,
  requested_by uuid not null
);

alter table public.tv_profiles      enable row level security;
alter table public.documents     enable row level security;
alter table public.doc_grants    enable row level security;
alter table public.audit_log     enable row level security;
alter table public.storage_purge enable row level security;
revoke all on public.tv_profiles, public.documents, public.doc_grants, public.audit_log, public.storage_purge from anon, authenticated;

-- audit log is append-only, even for privileged roles
create or replace function public.tvi_audit_immutable() returns trigger language plpgsql as $$
begin raise exception 'audit_log is append-only'; end $$;
drop trigger if exists audit_log_immutable on public.audit_log;
create trigger audit_log_immutable before update or delete on public.audit_log
  for each row execute function public.tvi_audit_immutable();
drop trigger if exists audit_log_no_truncate on public.audit_log;
create trigger audit_log_no_truncate before truncate on public.audit_log
  for each statement execute function public.tvi_audit_immutable();

-- ---------- internal helpers (not callable from the browser) ----------
create or replace function public.tvi_deny(msg text, det text default null, doc uuid default null)
returns void language plpgsql as $$
begin raise exception '%', msg using errcode = 'TV001', detail = coalesce(det,''), hint = coalesce(doc::text,''); end $$;

-- p_docname is only used to label the audit entry when there is no document row yet (uploads)
create or replace function public.tvi_invalid(msg text, doc uuid default null, p_docname text default null)
returns void language plpgsql as $$
begin raise exception '%', msg using errcode = 'TV002', detail = coalesce(p_docname,''), hint = coalesce(doc::text,''); end $$;

create or replace function public.tvi_rank(p text) returns int language sql immutable as $$
  select case p when 'read' then 1 when 'edit' then 2 when 'owner' then 3 else 0 end $$;

create or replace function public.tvi_ext(p_name text) returns text language sql immutable as $$
  select lower(coalesce(substring(p_name from '\.([^.]*)$'), '')) $$;

create or replace function public.tvi_hash(prev text, seq bigint, ts timestamptz, actor uuid, actor_name text,
  action text, doc_id uuid, doc_name text, outcome text, detail text)
returns text language sql stable as $$
  select encode(extensions.digest(convert_to(prev || jsonb_build_array(seq,
    to_char(ts at time zone 'utc','YYYY-MM-DD"T"HH24:MI:SS.US'), actor::text, actor_name, action,
    doc_id::text, doc_name, outcome, detail)::text, 'utf8'), 'sha256'), 'hex') $$;

create or replace function public.tvi_audit(p_actor uuid, p_action text, p_doc uuid, p_doc_name text,
  p_outcome text, p_detail text default '')
returns void language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare prev text; n bigint; t timestamptz := clock_timestamp(); an text; dtl text := coalesce(p_detail,'');
begin
  perform pg_advisory_xact_lock(727001);          -- one writer at a time keeps the chain in order
  select hash, seq into prev, n from audit_log order by seq desc limit 1;
  prev := coalesce(prev,'0'); n := coalesce(n,0) + 1;
  select name into an from tv_profiles where id = p_actor;
  insert into audit_log values (n, t, p_actor, an, p_action, p_doc, p_doc_name, p_outcome, dtl, prev,
    tvi_hash(prev, n, t, p_actor, an, p_action, p_doc, p_doc_name, p_outcome, dtl));
end $$;

create or replace function public.tvi_verify() returns bigint
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare r audit_log; prev text := '0'; expect bigint := 1;
begin
  for r in select * from audit_log order by seq loop
    if r.seq <> expect or r.prev <> prev
       or r.hash <> tvi_hash(prev, r.seq, r.ts, r.actor, r.actor_name, r.action, r.doc_id, r.doc_name, r.outcome, r.detail)
    then return r.seq; end if;
    prev := r.hash; expect := expect + 1;
  end loop;
  return 0;
end $$;

create or replace function public.tvi_active(uid uuid) returns tv_profiles
language plpgsql security definer set search_path = public, pg_temp as $$
declare u tv_profiles;
begin
  select * into u from tv_profiles where id = uid;
  if not found or not u.active or not u.approved then perform tvi_deny('Account is not active'); end if;
  return u;
end $$;

create or replace function public.tvi_role(uid uuid, roles text[]) returns tv_profiles
language plpgsql security definer set search_path = public, pg_temp as $$
declare u tv_profiles;
begin
  u := tvi_active(uid);
  if not (u.role = any(roles)) then perform tvi_deny('Your role cannot do this', 'role ' || u.role); end if;
  return u;
end $$;

create or replace function public.tvi_level(uid uuid, d documents) returns text
language sql stable security definer set search_path = public, pg_temp as $$
  select case when d.owner_id = uid then 'owner'
    else coalesce(
      (select g.perm from doc_grants g where g.doc_id = d.id and g.user_id = uid),
      case when d.visibility = 'everyone'
            and exists (select 1 from tv_profiles p where p.id = uid and p.role <> 'admin')
           then 'read' end) end $$;

create or replace function public.tvi_need(uid uuid, p_id uuid, p_min text) returns documents
language plpgsql security definer set search_path = public, pg_temp as $$
declare d documents; lv text;
begin
  perform tvi_active(uid);
  select * into d from documents where documents.id = p_id;
  if found then lv := tvi_level(uid, d); end if;
  if lv is null or tvi_rank(lv) < tvi_rank(p_min) then
    perform tvi_deny('Document not found, or you do not have permission', 'needs ' || p_min, p_id);
  end if;
  return d;
end $$;

create or replace function public.tvi_fail(p_actor uuid, p_action text, p_state text, p_msg text, p_det text, p_hint text)
returns jsonb language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare did uuid := nullif(p_hint,'')::uuid; dname text;
begin
  if p_state not in ('TV001','TV002') then raise exception '%', p_msg; end if;
  select name into dname from documents where id = did;
  if p_state = 'TV001' then
    perform tvi_audit(p_actor, p_action, did, dname, 'denied', coalesce(p_det,''));
    return jsonb_build_object('ok', false, 'kind', 'denied', 'error', p_msg);
  end if;
  perform tvi_audit(p_actor, p_action, did, coalesce(dname, nullif(p_det,'')), 'rejected', p_msg);
  return jsonb_build_object('ok', false, 'kind', 'invalid', 'error', p_msg);
end $$;

create or replace function public.tvi_check_name(p_name text) returns void language plpgsql as $$
begin
  if p_name is null or p_name !~ '^[A-Za-z0-9_ ().-]{1,100}$' or position('..' in p_name) > 0 or left(p_name,1) = '.' then
    perform tvi_invalid('File name: 1-100 characters, letters, digits, space, dot, dash, underscore, brackets only', null, p_name);
  end if;
  if tvi_ext(p_name) <> all (array['txt','md','csv','json','pdf','png']) then
    perform tvi_invalid('File type .' || tvi_ext(p_name) || ' is not allowed (txt, md, csv, json, pdf, png)', null, p_name);
  end if;
end $$;

create or replace function public.tvi_check_cat(p text) returns void language plpgsql as $$
begin
  if p is null or p <> all (array['Contract','HR','Finance','Engineering','Audit','Other']) then perform tvi_invalid('Unknown category'); end if;
end $$;

-- confirms a staged Storage object belongs to the caller, exists, has a legal size and is unused
create or replace function public.tvi_check_object(uid uuid, p_path text, p_label text, p_doc uuid default null) returns bigint
language plpgsql security definer set search_path = public, pg_temp as $$
declare sz bigint;
begin
  select (metadata->>'size')::bigint into sz from storage.objects where bucket_id = 'vault' and name = p_path;
  if not found then perform tvi_invalid('The uploaded file was not found', p_doc, p_label); end if;
  if split_part(p_path,'/',1) <> uid::text then perform tvi_invalid('The uploaded file does not belong to you', p_doc, p_label); end if;
  if sz is null or sz < 1 then perform tvi_invalid('File is empty', p_doc, p_label); end if;
  if sz > 1048576 then perform tvi_invalid('File is larger than 1 MB', p_doc, p_label); end if;
  if exists (select 1 from documents where storage_path = p_path) then perform tvi_invalid('That upload is already in use', p_doc, p_label); end if;
  return sz;
end $$;

create or replace function public.tvi_meta(d documents, uid uuid) returns jsonb
language sql stable security definer set search_path = public, pg_temp as $$
  select jsonb_build_object('id', d.id, 'name', d.name, 'ext', d.ext, 'category', d.category, 'owner', d.owner_id,
    'size', d.size, 'created', d.created_at, 'modified', d.modified_at, 'version', d.version,
    'visibility', d.visibility, 'access', case when uid is null then null else tvi_level(uid, d) end) $$;

create or replace function public.tvi_user(u tv_profiles) returns jsonb language sql immutable as $$
  select jsonb_build_object('id', ($1).id, 'username', ($1).username, 'name', ($1).name, 'role', ($1).role,
    'active', ($1).active, 'approved', ($1).approved) $$;

-- ---------- sign-up: every new auth user gets a pending profile --------
create or replace function public.tvi_new_user() returns trigger
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare
  un text := lower(trim(coalesce(new.raw_user_meta_data->>'username','')));
  nm text := trim(coalesce(new.raw_user_meta_data->>'name',''));
  r  text := coalesce(new.raw_user_meta_data->>'role','viewer');
begin
  if un !~ '^[a-z0-9_.-]{3,30}$' then raise exception 'Invalid username'; end if;
  if char_length(nm) not between 2 and 60 then raise exception 'Invalid name'; end if;
  if r not in ('owner','viewer') then r := 'viewer'; end if;   -- admins can never self-register
  insert into tv_profiles (id, username, name, role, active, approved) values (new.id, un, nm, r, true, false);
  perform tvi_audit(new.id, 'REGISTER', null, null, 'allowed', 'role ' || r || ', awaiting approval');
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.tvi_new_user();

-- ---------- public API (all return {ok, data} or {ok:false, kind, error}) --
create or replace function public.tv_username_free(p_username text) returns boolean
language sql stable security definer set search_path = public, pg_temp as $$
  select not exists (select 1 from tv_profiles where username = lower(trim(p_username))) $$;

create or replace function public.tv_me() returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare uid uuid := auth.uid(); u tv_profiles; st text; mg text; dt text; ht text;
begin
  u := tvi_active(uid);
  return jsonb_build_object('ok', true, 'data', tvi_user(u));
exception when others then
  get stacked diagnostics st = returned_sqlstate, mg = message_text, dt = pg_exception_detail, ht = pg_exception_hint;
  return tvi_fail(uid, 'SESSION', st, mg, dt, ht);
end $$;

create or replace function public.tv_login() returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare uid uuid := auth.uid(); u tv_profiles;
begin
  select * into u from tv_profiles where id = uid;
  if not found then
    perform tvi_audit(uid, 'LOGIN', null, null, 'denied', 'no profile');
    return jsonb_build_object('ok', false, 'kind', 'denied', 'error', 'Invalid credentials');
  elsif not u.approved then
    perform tvi_audit(uid, 'LOGIN', null, null, 'denied', 'awaiting approval');
    return jsonb_build_object('ok', false, 'kind', 'denied', 'error', 'Your account is waiting for administrator approval');
  elsif not u.active then
    perform tvi_audit(uid, 'LOGIN', null, null, 'denied', 'deactivated');
    return jsonb_build_object('ok', false, 'kind', 'denied', 'error', 'Account is not active');
  end if;
  perform tvi_audit(uid, 'LOGIN', null, null, 'allowed');
  return jsonb_build_object('ok', true, 'data', tvi_user(u));
end $$;

create or replace function public.tv_users() returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare uid uuid := auth.uid(); u tv_profiles; r jsonb; st text; mg text; dt text; ht text;
begin
  u := tvi_active(uid);
  select coalesce(jsonb_agg(tvi_user(p) order by p.name), '[]'::jsonb) into r
    from tv_profiles p where u.role = 'admin' or p.approved;
  return jsonb_build_object('ok', true, 'data', r);
exception when others then
  get stacked diagnostics st = returned_sqlstate, mg = message_text, dt = pg_exception_detail, ht = pg_exception_hint;
  return tvi_fail(uid, 'LIST_USERS', st, mg, dt, ht);
end $$;

create or replace function public.tv_list(p_q text default null, p_owner uuid default null, p_cat text default null,
  p_from date default null, p_to date default null) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare uid uuid := auth.uid(); r jsonb; st text; mg text; dt text; ht text;
begin
  perform tvi_active(uid);
  select coalesce(jsonb_agg(tvi_meta(d, uid) order by d.created_at), '[]'::jsonb) into r
    from documents d
   where tvi_level(uid, d) is not null
     and (coalesce(p_q,'') = '' or position(lower(p_q) in lower(d.name)) > 0)
     and (p_owner is null or d.owner_id = p_owner)
     and (p_cat is null or p_cat = '' or d.category = p_cat)
     and (p_from is null or d.created_at::date >= p_from)
     and (p_to is null or d.created_at::date <= p_to);
  return jsonb_build_object('ok', true, 'data', r);
exception when others then
  get stacked diagnostics st = returned_sqlstate, mg = message_text, dt = pg_exception_detail, ht = pg_exception_hint;
  return tvi_fail(uid, 'LIST', st, mg, dt, ht);
end $$;

-- opening a document: logs READ and hands back the storage path (Storage only releases the file shortly after)
create or replace function public.tv_read(p_id uuid) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare uid uuid := auth.uid(); d documents; st text; mg text; dt text; ht text;
begin
  d := tvi_need(uid, p_id, 'read');
  perform tvi_audit(uid, 'READ', d.id, d.name, 'allowed');
  return jsonb_build_object('ok', true, 'data', jsonb_build_object('meta', tvi_meta(d, uid), 'path', d.storage_path));
exception when others then
  get stacked diagnostics st = returned_sqlstate, mg = message_text, dt = pg_exception_detail, ht = pg_exception_hint;
  return tvi_fail(uid, 'READ', st, mg, dt, ht);
end $$;

create or replace function public.tv_download(p_id uuid) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare uid uuid := auth.uid(); d documents; st text; mg text; dt text; ht text;
begin
  d := tvi_need(uid, p_id, 'read');
  perform tvi_audit(uid, 'DOWNLOAD', d.id, d.name, 'allowed');
  return jsonb_build_object('ok', true, 'data', jsonb_build_object('name', d.name, 'path', d.storage_path));
exception when others then
  get stacked diagnostics st = returned_sqlstate, mg = message_text, dt = pg_exception_detail, ht = pg_exception_hint;
  return tvi_fail(uid, 'DOWNLOAD', st, mg, dt, ht);
end $$;

-- panel data for an open document (no audit entry; READ was logged when it was opened)
create or replace function public.tv_detail(p_id uuid) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare uid uuid := auth.uid(); d documents; lv text; eds jsonb; gr jsonb := null; au jsonb := null;
        st text; mg text; dt text; ht text;
begin
  d := tvi_need(uid, p_id, 'read');
  lv := tvi_level(uid, d);
  select coalesce(jsonb_agg(x), '[]'::jsonb) into eds from (
    select d.owner_id as x union all select g.user_id from doc_grants g where g.doc_id = p_id and g.perm = 'edit') s;
  if lv = 'owner' then
    select coalesce(jsonb_agg(jsonb_build_object('user', g.user_id, 'perm', g.perm)), '[]'::jsonb) into gr
      from doc_grants g where g.doc_id = p_id;
    select coalesce(jsonb_agg(to_jsonb(a) order by a.seq), '[]'::jsonb) into au
      from (select * from audit_log where doc_id = p_id order by seq desc limit 100) a;
  end if;
  return jsonb_build_object('ok', true, 'data',
    jsonb_build_object('meta', tvi_meta(d, uid), 'editors', eds, 'grants', gr, 'audit', au));
exception when others then
  get stacked diagnostics st = returned_sqlstate, mg = message_text, dt = pg_exception_detail, ht = pg_exception_hint;
  return tvi_fail(uid, 'VIEW_DETAIL', st, mg, dt, ht);
end $$;

-- the file must already be staged in Storage at <your uid>/<random uuid>
create or replace function public.tv_upload(p_name text, p_path text, p_cat text, p_vis text, p_editors uuid[] default '{}')
returns jsonb language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare uid uuid := auth.uid(); sz bigint; ed uuid; t tv_profiles; d documents; names text[] := '{}';
        st text; mg text; dt text; ht text;
begin
  perform tvi_role(uid, array['owner']);
  perform tvi_check_name(p_name);
  sz := tvi_check_object(uid, p_path, p_name);
  perform tvi_check_cat(p_cat);
  if p_vis is null or p_vis not in ('everyone','private') then perform tvi_invalid('Choose who can view', null, p_name); end if;
  foreach ed in array coalesce(p_editors, '{}') loop
    select * into t from tv_profiles where id = ed;
    if not found or not t.active or not t.approved or t.role <> 'owner' or ed = uid then
      perform tvi_invalid('Editors must be other document owners', null, p_name);
    end if;
    names := names || t.name;
  end loop;
  insert into documents (name, ext, category, owner_id, size, visibility, storage_path)
    values (p_name, tvi_ext(p_name), p_cat, uid, sz, p_vis, p_path) returning * into d;
  foreach ed in array coalesce(p_editors, '{}') loop
    insert into doc_grants values (d.id, ed, 'edit') on conflict do nothing;
  end loop;
  perform tvi_audit(uid, 'UPLOAD', d.id, d.name, 'allowed',
    sz || ' bytes, view: ' || case when p_vis = 'everyone' then 'everyone' else 'chosen people only' end
    || case when cardinality(names) > 0 then ', editors: ' || array_to_string(names, ', ') else '' end);
  return jsonb_build_object('ok', true, 'data', tvi_meta(d, uid));
exception when others then
  get stacked diagnostics st = returned_sqlstate, mg = message_text, dt = pg_exception_detail, ht = pg_exception_hint;
  return tvi_fail(uid, 'UPLOAD', st, mg, dt, ht);
end $$;

-- p_path is a newly staged object when the text content changed, otherwise null
create or replace function public.tv_edit(p_id uuid, p_name text default null, p_cat text default null, p_path text default null)
returns jsonb language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare uid uuid := auth.uid(); d documents; parts text[] := '{}'; nname text; ncat text; npath text; nsz int;
        oldp text := null; st text; mg text; dt text; ht text;
begin
  d := tvi_need(uid, p_id, 'edit');
  nname := d.name; ncat := d.category; npath := d.storage_path; nsz := d.size;
  if p_name is not null and p_name <> d.name then
    if tvi_ext(p_name) <> d.ext then perform tvi_invalid('The file extension cannot change', d.id); end if;
    perform tvi_check_name(p_name);
    nname := p_name; parts := array_append(parts, 'name');
  end if;
  if p_cat is not null and p_cat <> d.category then
    perform tvi_check_cat(p_cat); ncat := p_cat; parts := array_append(parts, 'category');
  end if;
  if p_path is not null then
    if d.ext <> all (array['txt','md','csv','json']) then perform tvi_invalid('Only text documents can be edited here', d.id); end if;
    nsz := tvi_check_object(uid, p_path, d.name, d.id);
    oldp := d.storage_path; npath := p_path; parts := array_append(parts, 'content');
  end if;
  if cardinality(parts) = 0 then return jsonb_build_object('ok', true, 'data', null); end if;
  update documents set name = nname, category = ncat, storage_path = npath, size = nsz,
         version = version + 1, modified_at = now() where id = d.id returning * into d;
  if oldp is not null then
    insert into storage_purge values (oldp, uid) on conflict (path) do update set requested_by = excluded.requested_by;
  end if;
  perform tvi_audit(uid, 'CHANGE', d.id, d.name, 'allowed', array_to_string(parts, ', ') || ' (v' || d.version || ')');
  return jsonb_build_object('ok', true, 'data', jsonb_build_object('old_path', oldp));
exception when others then
  get stacked diagnostics st = returned_sqlstate, mg = message_text, dt = pg_exception_detail, ht = pg_exception_hint;
  return tvi_fail(uid, 'CHANGE', st, mg, dt, ht);
end $$;

create or replace function public.tv_remove(p_id uuid) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare uid uuid := auth.uid(); d documents; st text; mg text; dt text; ht text;
begin
  d := tvi_need(uid, p_id, 'owner');
  perform tvi_audit(uid, 'DELETE', d.id, d.name, 'allowed');
  insert into storage_purge values (d.storage_path, uid) on conflict (path) do update set requested_by = excluded.requested_by;
  delete from documents where id = d.id;
  return jsonb_build_object('ok', true, 'data', jsonb_build_object('path', d.storage_path));
exception when others then
  get stacked diagnostics st = returned_sqlstate, mg = message_text, dt = pg_exception_detail, ht = pg_exception_hint;
  return tvi_fail(uid, 'DELETE', st, mg, dt, ht);
end $$;

create or replace function public.tv_purged(p_paths text[]) returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
begin
  delete from storage_purge where requested_by = auth.uid() and path = any(p_paths);
  return jsonb_build_object('ok', true, 'data', null);
end $$;

create or replace function public.tv_grant(p_id uuid, p_target uuid, p_perm text) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare uid uuid := auth.uid(); d documents; t tv_profiles; st text; mg text; dt text; ht text;
begin
  d := tvi_need(uid, p_id, 'owner');
  select * into t from tv_profiles where id = p_target;
  if not found or not t.active or not t.approved or p_target = uid or p_perm is null or p_perm not in ('read','edit') then
    perform tvi_invalid('Choose another active person and read or edit', p_id);
  end if;
  if p_perm = 'edit' and t.role <> 'owner' then perform tvi_invalid('Only document owners can be given edit access', p_id); end if;
  if p_perm = 'read' and d.visibility = 'everyone' then perform tvi_invalid('Everyone can already view this document', p_id); end if;
  insert into doc_grants values (p_id, p_target, p_perm)
    on conflict (doc_id, user_id) do update set perm = excluded.perm;
  perform tvi_audit(uid, 'PERMISSION_GRANT', d.id, d.name, 'allowed', 'to ' || t.name || ': ' || p_perm);
  return jsonb_build_object('ok', true, 'data', null);
exception when others then
  get stacked diagnostics st = returned_sqlstate, mg = message_text, dt = pg_exception_detail, ht = pg_exception_hint;
  return tvi_fail(uid, 'PERMISSION_GRANT', st, mg, dt, ht);
end $$;

create or replace function public.tv_revoke(p_id uuid, p_target uuid) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare uid uuid := auth.uid(); d documents; tname text; st text; mg text; dt text; ht text;
begin
  d := tvi_need(uid, p_id, 'owner');
  if not exists (select 1 from doc_grants where doc_id = p_id and user_id = p_target) then perform tvi_invalid('No such grant', p_id); end if;
  select name into tname from tv_profiles where id = p_target;
  delete from doc_grants where doc_id = p_id and user_id = p_target;
  perform tvi_audit(uid, 'PERMISSION_REVOKE', d.id, d.name, 'allowed', 'from ' || tname);
  return jsonb_build_object('ok', true, 'data', null);
exception when others then
  get stacked diagnostics st = returned_sqlstate, mg = message_text, dt = pg_exception_detail, ht = pg_exception_hint;
  return tvi_fail(uid, 'PERMISSION_REVOKE', st, mg, dt, ht);
end $$;

create or replace function public.tv_set_visibility(p_id uuid, p_vis text) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare uid uuid := auth.uid(); d documents; st text; mg text; dt text; ht text;
begin
  d := tvi_need(uid, p_id, 'owner');
  if p_vis is null or p_vis not in ('everyone','private') then perform tvi_invalid('Choose who can view', p_id); end if;
  if d.visibility <> p_vis then
    update documents set visibility = p_vis where id = p_id;
    perform tvi_audit(uid, 'VISIBILITY_CHANGE', d.id, d.name, 'allowed',
      'view: ' || case when p_vis = 'everyone' then 'everyone' else 'chosen people only' end);
  end if;
  return jsonb_build_object('ok', true, 'data', null);
exception when others then
  get stacked diagnostics st = returned_sqlstate, mg = message_text, dt = pg_exception_detail, ht = pg_exception_hint;
  return tvi_fail(uid, 'VISIBILITY_CHANGE', st, mg, dt, ht);
end $$;

-- ---------- administration ---------------------------------------------
create or replace function public.tv_admin_view() returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare uid uuid := auth.uid(); lg jsonb; dc jsonb; st text; mg text; dt text; ht text;
begin
  perform tvi_role(uid, array['admin']);
  select coalesce(jsonb_agg(to_jsonb(a) order by a.seq), '[]'::jsonb) into lg
    from (select * from audit_log order by seq desc limit 500) a;
  select coalesce(jsonb_agg(tvi_meta(d, null) || jsonb_build_object('acl',
      (select coalesce(jsonb_object_agg(g.user_id, g.perm), '{}'::jsonb) from doc_grants g where g.doc_id = d.id))
      order by d.created_at), '[]'::jsonb) into dc
    from documents d;
  return jsonb_build_object('ok', true, 'data', jsonb_build_object('log', lg, 'docs', dc));
exception when others then
  get stacked diagnostics st = returned_sqlstate, mg = message_text, dt = pg_exception_detail, ht = pg_exception_hint;
  return tvi_fail(uid, 'ADMIN_VIEW', st, mg, dt, ht);
end $$;

create or replace function public.tv_set_active(p_target uuid, p_on boolean) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare uid uuid := auth.uid(); t tv_profiles; st text; mg text; dt text; ht text;
begin
  perform tvi_role(uid, array['admin']);
  select * into t from tv_profiles where id = p_target;
  if not found or p_target = uid then perform tvi_invalid('Choose another user'); end if;
  update tv_profiles set active = p_on where id = p_target;
  perform tvi_audit(uid, case when p_on then 'USER_ACTIVATE' else 'USER_DEACTIVATE' end, null, null, 'allowed', t.name);
  return jsonb_build_object('ok', true, 'data', null);
exception when others then
  get stacked diagnostics st = returned_sqlstate, mg = message_text, dt = pg_exception_detail, ht = pg_exception_hint;
  return tvi_fail(uid, 'USER_STATUS', st, mg, dt, ht);
end $$;

create or replace function public.tv_set_role(p_target uuid, p_role text) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare uid uuid := auth.uid(); t tv_profiles; old text; st text; mg text; dt text; ht text;
begin
  perform tvi_role(uid, array['admin']);
  select * into t from tv_profiles where id = p_target;
  if not found or not t.approved or t.role = 'admin' or p_target = uid or p_role is null or p_role not in ('viewer','owner') then
    perform tvi_invalid('Choose a viewer or owner account, and the role viewer or owner');
  end if;
  if t.role = p_role then return jsonb_build_object('ok', true, 'data', null); end if;
  if p_role = 'viewer' then
    if exists (select 1 from documents where owner_id = p_target) then
      perform tvi_invalid(t.name || ' still owns documents; they must be deleted first');
    end if;
    delete from doc_grants where user_id = p_target and perm = 'edit';
  end if;
  old := t.role;
  update tv_profiles set role = p_role where id = p_target;
  perform tvi_audit(uid, 'ROLE_CHANGE', null, null, 'allowed', t.name || ': ' || old || ' to ' || p_role);
  return jsonb_build_object('ok', true, 'data', null);
exception when others then
  get stacked diagnostics st = returned_sqlstate, mg = message_text, dt = pg_exception_detail, ht = pg_exception_hint;
  return tvi_fail(uid, 'ROLE_CHANGE', st, mg, dt, ht);
end $$;

create or replace function public.tv_approve(p_target uuid) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare uid uuid := auth.uid(); t tv_profiles; st text; mg text; dt text; ht text;
begin
  perform tvi_role(uid, array['admin']);
  select * into t from tv_profiles where id = p_target;
  if not found or t.approved then perform tvi_invalid('No pending registration'); end if;
  update tv_profiles set approved = true where id = p_target;
  perform tvi_audit(uid, 'REGISTER_APPROVE', null, null, 'allowed', t.name || ' (' || t.role || ')');
  return jsonb_build_object('ok', true, 'data', null);
exception when others then
  get stacked diagnostics st = returned_sqlstate, mg = message_text, dt = pg_exception_detail, ht = pg_exception_hint;
  return tvi_fail(uid, 'REGISTER_APPROVE', st, mg, dt, ht);
end $$;

create or replace function public.tv_reject(p_target uuid) returns jsonb
language plpgsql security definer set search_path = public, extensions, auth, pg_temp as $$
declare uid uuid := auth.uid(); t tv_profiles; st text; mg text; dt text; ht text;
begin
  perform tvi_role(uid, array['admin']);
  select * into t from tv_profiles where id = p_target;
  if not found or t.approved then perform tvi_invalid('No pending registration'); end if;
  perform tvi_audit(uid, 'REGISTER_REJECT', null, null, 'allowed', t.name);
  delete from auth.users where id = p_target;      -- cascades to the profile
  return jsonb_build_object('ok', true, 'data', null);
exception when others then
  get stacked diagnostics st = returned_sqlstate, mg = message_text, dt = pg_exception_detail, ht = pg_exception_hint;
  return tvi_fail(uid, 'REGISTER_REJECT', st, mg, dt, ht);
end $$;

create or replace function public.tv_verify() returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare uid uuid := auth.uid(); r bigint; st text; mg text; dt text; ht text;
begin
  perform tvi_role(uid, array['admin']);
  r := tvi_verify();
  return jsonb_build_object('ok', true, 'data', r);
exception when others then
  get stacked diagnostics st = returned_sqlstate, mg = message_text, dt = pg_exception_detail, ht = pg_exception_hint;
  return tvi_fail(uid, 'VERIFY', st, mg, dt, ht);
end $$;

-- ---------- Storage: private bucket, same rules ------------------------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('vault', 'vault', false, 1048576,
  array['text/plain','text/markdown','text/csv','application/json','application/pdf','image/png'])
on conflict (id) do update set public = false, file_size_limit = 1048576,
  allowed_mime_types = excluded.allowed_mime_types;

-- only active, approved document owners may stage files, and only in their own folder
create or replace function public.tvi_can_upload(p_name text) returns boolean
language sql stable security definer set search_path = public, pg_temp as $$
  select exists (select 1 from tv_profiles p where p.id = auth.uid() and p.active and p.approved and p.role = 'owner')
     and split_part(p_name, '/', 1) = auth.uid()::text
     and p_name ~ '^[0-9a-f-]{36}/[0-9a-f-]{36}$' $$;

-- a file can be fetched only if the caller has a grant on the document AND the
-- READ/DOWNLOAD audit entry was written in the last two minutes
create or replace function public.tvi_can_fetch(p_name text) returns boolean
language sql stable security definer set search_path = public, pg_temp as $$
  select exists (
    select 1 from documents d
    join tv_profiles p on p.id = auth.uid() and p.active and p.approved
    where d.storage_path = p_name
      and tvi_level(auth.uid(), d) is not null
      and exists (select 1 from audit_log a
                  where a.actor = auth.uid() and a.doc_id = d.id and a.action in ('READ','DOWNLOAD')
                    and a.outcome = 'allowed' and a.ts > now() - interval '2 minutes')) $$;

-- removing: leftovers of your own failed uploads, or files the database told you to purge
create or replace function public.tvi_can_delete(p_name text) returns boolean
language sql stable security definer set search_path = public, pg_temp as $$
  select exists (select 1 from storage_purge s where s.path = p_name and s.requested_by = auth.uid())
      or (split_part(p_name, '/', 1) = auth.uid()::text
          and not exists (select 1 from documents d where d.storage_path = p_name)) $$;

drop policy if exists "vault insert" on storage.objects;
drop policy if exists "vault select" on storage.objects;
drop policy if exists "vault delete" on storage.objects;
create policy "vault insert" on storage.objects for insert to authenticated
  with check (bucket_id = 'vault' and public.tvi_can_upload(name));
create policy "vault select" on storage.objects for select to authenticated
  using (bucket_id = 'vault' and public.tvi_can_fetch(name));
create policy "vault delete" on storage.objects for delete to authenticated
  using (bucket_id = 'vault' and public.tvi_can_delete(name));

-- ---------- permissions on functions -----------------------------------
do $$
declare r record;
begin
  for r in select p.oid::regprocedure as sig, p.proname
             from pg_proc p join pg_namespace n on n.oid = p.pronamespace
            where n.nspname = 'public' and p.proname like 'tv%' loop
    execute format('revoke all on function %s from public, anon, authenticated', r.sig);
    if r.proname like 'tv\_%' or r.proname in ('tvi_can_upload','tvi_can_fetch','tvi_can_delete') then
      execute format('grant execute on function %s to authenticated', r.sig);
    end if;
  end loop;
end $$;
grant execute on function public.tv_username_free(text) to anon;

-- =====================================================================
-- First administrator (run AFTER registering that person in the app):
--   update public.tv_profiles set role = 'admin', approved = true where username = 'your-username';
-- =====================================================================
