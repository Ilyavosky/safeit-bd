create function public.guard_scan_domain()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if not exists (
    select 1 from public.domains d
    where d.id = new.domain_id and d.status = 'verified'
  ) then
    raise exception 'scan blocked: domain % is not verified', new.domain_id
      using errcode = 'check_violation';
  end if;
  return new;
end;
$$;

create trigger scans_guard_domain_trg
  before insert on public.scans
  for each row execute function public.guard_scan_domain();

create function public.guard_test_run()
returns trigger
language plpgsql
set search_path = ''
as $$
declare
  v_scan_type varchar;
  v_scan_domain uuid;
  v_domain_status varchar;
  v_whitelisted boolean;
  v_in_scope boolean;
  v_endpoint_domain uuid;
  v_tool_active boolean;
  v_validated boolean;
  v_kind varchar;
begin
  select s.type, s.domain_id, d.status
    into v_scan_type, v_scan_domain, v_domain_status
    from public.scans s
    join public.domains d on d.id = s.domain_id
    where s.id = new.scan_id;

  if v_scan_type is distinct from 'tests' then
    raise exception 'test run blocked: scan % is not a tests scan', new.scan_id
      using errcode = 'check_violation';
  end if;

  if v_domain_status is distinct from 'verified' then
    raise exception 'test run blocked: domain of scan % is not verified', new.scan_id
      using errcode = 'check_violation';
  end if;

  select e.whitelisted, a.in_scope, a.domain_id
    into v_whitelisted, v_in_scope, v_endpoint_domain
    from public.endpoints e
    join public.assets a on a.id = e.asset_id
    where e.id = new.endpoint_id;

  if v_endpoint_domain is distinct from v_scan_domain then
    raise exception 'test run blocked: endpoint % is outside the scan domain', new.endpoint_id
      using errcode = 'check_violation';
  end if;

  if not coalesce(v_in_scope, false) then
    raise exception 'test run blocked: asset of endpoint % is out of scope', new.endpoint_id
      using errcode = 'check_violation';
  end if;

  if not coalesce(v_whitelisted, false) then
    raise exception 'test run blocked: endpoint % is not whitelisted', new.endpoint_id
      using errcode = 'check_violation';
  end if;

  select t.active into v_tool_active from public.allowed_tools t where t.id = new.tool_id;
  if not coalesce(v_tool_active, false) then
    raise exception 'test run blocked: tool % is not active', new.tool_id
      using errcode = 'check_violation';
  end if;

  if new.decision_id is not null then
    select l.validated, l.kind into v_validated, v_kind
      from public.llm_decisions l where l.id = new.decision_id;
    if not coalesce(v_validated, false) or v_kind is distinct from 'plan' then
      raise exception 'test run blocked: decision % is not a validated plan', new.decision_id
        using errcode = 'check_violation';
    end if;
  end if;

  return new;
end;
$$;

create trigger test_runs_guard_trg
  before insert or update of scan_id, endpoint_id, tool_id, decision_id on public.test_runs
  for each row execute function public.guard_test_run();
