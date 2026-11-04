-- Patch: fixes 'malformed array literal' when saving changes. Safe to run; keeps all data.
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
