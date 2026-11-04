create sequence public.audit_log_id_seq as bigint;

create table public.audit_log (
  id bigint primary key,
  user_id uuid references public.users (id),
  action varchar(64) not null,
  entity varchar(64),
  entity_id uuid,
  detail jsonb not null default '{}'::jsonb,
  prev_hash varchar(64),
  hash varchar(64) not null,
  created_at timestamptz not null default now(),
  constraint audit_log_hash_key unique (hash)
);

alter sequence public.audit_log_id_seq owned by public.audit_log.id;

create function public.audit_log_row_hash(r public.audit_log)
returns varchar
language sql
immutable
set search_path = ''
as $$
  select encode(
    sha256(convert_to(
      concat_ws(
        '|',
        r.id::text,
        coalesce(r.prev_hash, ''),
        coalesce(r.user_id::text, ''),
        r.action,
        coalesce(r.entity, ''),
        coalesce(r.entity_id::text, ''),
        r.detail::text,
        extract(epoch from r.created_at)::text
      ),
      'UTF8'
    )),
    'hex'
  )::varchar;
$$;

create function public.audit_log_chain()
returns trigger
language plpgsql
set search_path = ''
as $$
declare
  last_hash varchar(64);
begin
  perform pg_advisory_xact_lock(hashtext('public.audit_log'));
  select a.hash into last_hash from public.audit_log a order by a.id desc limit 1;
  new.id := nextval('public.audit_log_id_seq');
  new.prev_hash := last_hash;
  new.hash := public.audit_log_row_hash(new);
  return new;
end;
$$;

create trigger audit_log_chain_trg
  before insert on public.audit_log
  for each row execute function public.audit_log_chain();

create function public.audit_log_block_changes()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  raise exception 'audit_log is append-only' using errcode = 'insufficient_privilege';
end;
$$;

create trigger audit_log_no_update_delete_trg
  before update or delete on public.audit_log
  for each row execute function public.audit_log_block_changes();

create trigger audit_log_no_truncate_trg
  before truncate on public.audit_log
  for each statement execute function public.audit_log_block_changes();

create function public.verify_audit_chain()
returns bigint
language plpgsql
stable
set search_path = ''
as $$
declare
  r public.audit_log;
  expected_prev varchar(64) := null;
begin
  for r in select * from public.audit_log order by id loop
    if r.prev_hash is distinct from expected_prev then
      return r.id;
    end if;
    if public.audit_log_row_hash(r) <> r.hash then
      return r.id;
    end if;
    expected_prev := r.hash;
  end loop;
  return null;
end;
$$;
