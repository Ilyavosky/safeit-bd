create index refresh_tokens_user_id_idx on public.refresh_tokens (user_id);
create index refresh_tokens_family_id_idx on public.refresh_tokens (family_id);
create index refresh_tokens_replaced_by_idx on public.refresh_tokens (replaced_by);

create index scans_domain_id_idx on public.scans (domain_id);
create index scans_started_by_idx on public.scans (started_by);
create index scans_active_idx on public.scans (status) where status in ('queued', 'running');

create index assets_scan_id_idx on public.assets (scan_id);

create index llm_decisions_scan_kind_idx on public.llm_decisions (scan_id, kind);

create index test_runs_scan_id_idx on public.test_runs (scan_id);
create index test_runs_endpoint_id_idx on public.test_runs (endpoint_id);
create index test_runs_tool_id_idx on public.test_runs (tool_id);
create index test_runs_decision_id_idx on public.test_runs (decision_id);

create index findings_test_run_endpoint_idx on public.findings (test_run_id, endpoint_id);
create index findings_endpoint_id_idx on public.findings (endpoint_id);
create index findings_decision_id_idx on public.findings (decision_id);
create index findings_open_severity_idx on public.findings (severity, priority_score desc)
  where not is_false_positive and remediation_status <> 'fixed';

create index finding_cves_cve_id_idx on public.finding_cves (cve_id);

create index recommendations_report_priority_idx on public.recommendations (report_id, priority);
create index recommendations_finding_id_idx on public.recommendations (finding_id);

create index audit_log_user_id_idx on public.audit_log (user_id);
create index audit_log_entity_idx on public.audit_log (entity, entity_id);
create index audit_log_created_at_idx on public.audit_log (created_at desc);
