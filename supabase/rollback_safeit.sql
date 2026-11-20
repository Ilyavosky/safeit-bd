drop table if exists
  public.public_analysis_hosts,
  public.public_analyses,
  public.recommendations,
  public.reports,
  public.finding_cves,
  public.findings,
  public.test_runs,
  public.llm_decisions,
  public.cve_catalog,
  public.allowed_tools,
  public.endpoints,
  public.services,
  public.assets,
  public.scans,
  public.domains,
  public.refresh_tokens,
  public.audit_log,
  public.users
cascade;

drop function if exists public.verify_audit_chain();
drop function if exists public.audit_log_chain();
drop function if exists public.audit_log_block_changes();
drop function if exists public.audit_log_row_hash(public.audit_log);
drop function if exists public.guard_test_run();
drop function if exists public.guard_scan_domain();
drop sequence if exists public.audit_log_id_seq;
