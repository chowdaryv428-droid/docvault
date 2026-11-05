-- =====================================================================
-- TrustVault patch: admin approval of uploads + default admin access
-- Run ONCE in the Supabase SQL editor, AFTER supabase-schema.sql and
-- patch-tv_edit.sql. Safe to run again. Keeps all existing data:
-- documents that already exist are marked 'approved'.
--
-- What changes
--  1. Every owner upload starts as 'pending'. Only the owner and the
--     admin can see it; nobody else can open, download or be given it.
--  2. The admin can see, open, download and edit EVERY document.
--     Each admin open/download/edit is written to the audit log.
--  3. New tv_doc_approve / tv_doc_reject (admin only). Reject keeps a
--     'rejected' record so the owner sees it, and queues the file for
--     removal from Storage.
-- =====================================================================

-- 1. status column (existing rows become 'approved', new rows default to 'pending')
alter table public.documents
  add column if not exists status text not null default 'approved'
  check (status in ('pending','approved','rejected'));
alter table public.documents alter column status set default 'pending';

-- 2. who can see what ---------------------------------------------------
create or replace function public.tvi_level(uid uuid, d documents) returns text
language sql stable security definer set search_path = public, pg_temp as $$
  select case
    when d.owner_id = uid then 'owner'
    when exists (select 1 from tv_profiles p
                  where p.id = uid and p.role = 'admin' and p.active and p.approved) then 'edit'
    when d.status <> 'approved' then null          -- pending / rejected: owner and admin only
    else coalesce(
      (select g.perm from doc_grants g where g.doc_id = d.id and g.user_id = uid),
      case when d.visibility = 'everyone'
            and exists (select 1 from tv_profiles p where p.id = uid and p.role <> 'admin')
           then 'read' end)
  end $$;

-- rejected documents cannot be opened or changed by anyone; the owner may still remove the record
create or replace function public.tvi_need(uid uuid, p_id uuid, p_min text) returns documents
language plpgsql security definer set search_path = public, pg_temp as $$
declare d documents; lv text;
begin
  perform tvi_active(uid);
  select * into d from documents where documents.id = p_id;
  if found then
    lv := tvi_level(uid, d);
    if d.status = 'rejected' and p_min <> 'owner' then lv := null; end if;
  end if;
  if lv is null or tvi_rank(lv) < tvi_rank(p_min) then
    perform tvi_deny('Document not found, or you do not have permission', 'needs ' || p_min, p_id);
  end if;
  return d;
end $$;

-- the list and detail data now carry the status
create or replace function public.tvi_meta(d documents, uid uuid) returns jsonb
language sql stable security definer set search_path = public, pg_temp as $$
  select jsonb_build_object('id', d.id, 'name', d.name, 'ext', d.ext, 'category', d.category, 'owner', d.owner_id,
    'size', d.size, 'created', d.created_at, 'modified', d.modified_at, 'version', d.version,
    'visibility', d.visibility, 'status', d.status,
    'access', case when uid is null then null else tvi_level(uid, d) end) $$;

-- the admin may stage replacement content when editing a text document
create or replace function public.tvi_can_upload(p_name text) returns boolean
language sql stable security definer set search_path = public, pg_temp as $$
  select exists (select 1 from tv_profiles p where p.id = auth.uid() and p.active and p.approved
                    and p.role in ('owner','admin'))
     and split_part(p_name, '/', 1) = auth.uid()::text
     and p_name ~ '^[0-9a-f-]{36}/[0-9a-f-]{36}$' $$;

-- 3. uploads start as pending -----------------------------------------
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
  insert into documents (name, ext, category, owner_id, size, visibility, storage_path, status)
    values (p_name, tvi_ext(p_name), p_cat, uid, sz, p_vis, p_path, 'pending') returning * into d;
  foreach ed in array coalesce(p_editors, '{}') loop
    insert into doc_grants values (d.id, ed, 'edit') on conflict do nothing;
  end loop;
  perform tvi_audit(uid, 'UPLOAD', d.id, d.name, 'allowed',
    sz || ' bytes, view: ' || case when p_vis = 'everyone' then 'everyone' else 'chosen people only' end
    || case when cardinality(names) > 0 then ', editors: ' || array_to_string(names, ', ') else '' end
    || ', waiting for administrator approval');
  return jsonb_build_object('ok', true, 'data', tvi_meta(d, uid));
exception when others then
  get stacked diagnostics st = returned_sqlstate, mg = message_text, dt = pg_exception_detail, ht = pg_exception_hint;
  return tvi_fail(uid, 'UPLOAD', st, mg, dt, ht);
end $$;

-- 4. admin decisions ---------------------------------------------------
create or replace function public.tv_doc_approve(p_id uuid) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare uid uuid := auth.uid(); d documents; oname text; st text; mg text; dt text; ht text;
begin
  perform tvi_role(uid, array['admin']);
  select * into d from documents where documents.id = p_id;
  if not found or d.status <> 'pending' then perform tvi_invalid('No upload is waiting for approval', p_id); end if;
  update documents set status = 'approved' where documents.id = p_id returning * into d;
  select name into oname from tv_profiles where id = d.owner_id;
  perform tvi_audit(uid, 'UPLOAD_APPROVE', d.id, d.name, 'allowed', 'owner: ' || coalesce(oname, '?'));
  return jsonb_build_object('ok', true, 'data', tvi_meta(d, uid));
exception when others then
  get stacked diagnostics st = returned_sqlstate, mg = message_text, dt = pg_exception_detail, ht = pg_exception_hint;
  return tvi_fail(uid, 'UPLOAD_APPROVE', st, mg, dt, ht);
end $$;

create or replace function public.tv_doc_reject(p_id uuid) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare uid uuid := auth.uid(); d documents; oname text; st text; mg text; dt text; ht text;
begin
  perform tvi_role(uid, array['admin']);
  select * into d from documents where documents.id = p_id;
  if not found or d.status <> 'pending' then perform tvi_invalid('No upload is waiting for approval', p_id); end if;
  select name into oname from tv_profiles where id = d.owner_id;
  update documents set status = 'rejected', modified_at = now() where documents.id = p_id;
  insert into storage_purge values (d.storage_path, uid)
    on conflict (path) do update set requested_by = excluded.requested_by;
  perform tvi_audit(uid, 'UPLOAD_REJECT', d.id, d.name, 'allowed', 'owner: ' || coalesce(oname, '?'));
  return jsonb_build_object('ok', true, 'data', jsonb_build_object('path', d.storage_path));
exception when others then
  get stacked diagnostics st = returned_sqlstate, mg = message_text, dt = pg_exception_detail, ht = pg_exception_hint;
  return tvi_fail(uid, 'UPLOAD_REJECT', st, mg, dt, ht);
end $$;

-- 5. permissions on the functions (same rule as the main schema) -------
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
