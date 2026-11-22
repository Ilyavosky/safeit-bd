do $$
declare
  t text;
begin
  foreach t in array array[
    'users',
    'refresh_tokens',
    'password_reset_tokens',
    'domains',
    'scans',
    'assets',
    'services',
    'endpoints',
    'allowed_tools',
    'cve_catalog',
    'llm_decisions',
    'test_runs',
    'findings',
    'finding_cves',
    'reports',
    'recommendations',
    'audit_log',
    'public_analyses',
    'public_analysis_hosts'
  ]
  loop
    execute format('alter table public.%I enable row level security', t);
    execute format('alter table public.%I force row level security', t);
    execute format('drop policy if exists deny_client_roles on public.%I', t);
    execute format(
      'create policy deny_client_roles on public.%I as restrictive for all to anon, authenticated using (false) with check (false)',
      t
    );
  end loop;
end
$$;

alter table public.users
  add constraint users_email_len_chk
    check (length(email) between 3 and 320 and position('@' in email) > 1) not valid,
  add constraint users_password_hash_len_chk check (length(password_hash) <= 255) not valid,
  add constraint users_totp_secret_len_chk
    check (totp_secret_enc is null or length(totp_secret_enc) <= 512) not valid;

alter table public.services
  add constraint services_banner_len_chk check (banner is null or length(banner) <= 4096) not valid;

alter table public.llm_decisions
  add constraint llm_decisions_justification_len_chk
    check (justification is null or length(justification) <= 20000) not valid;

alter table public.findings
  add constraint findings_fp_justification_len_chk
    check (fp_justification is null or length(fp_justification) <= 20000) not valid;

alter table public.reports
  add constraint reports_summary_len_chk check (length(summary) <= 20000) not valid,
  add constraint reports_content_len_chk check (length(content) <= 500000) not valid;

alter table public.recommendations
  add constraint recommendations_action_len_chk check (length(action) <= 5000) not valid;

alter table public.public_analyses
  add constraint public_analyses_summary_len_chk
    check (summary is null or length(summary) <= 20000) not valid;

alter table public.audit_log
  add constraint audit_log_detail_size_chk check (pg_column_size(detail) <= 65536) not valid;

alter table public.users validate constraint users_email_len_chk;
alter table public.users validate constraint users_password_hash_len_chk;
alter table public.users validate constraint users_totp_secret_len_chk;
alter table public.services validate constraint services_banner_len_chk;
alter table public.llm_decisions validate constraint llm_decisions_justification_len_chk;
alter table public.findings validate constraint findings_fp_justification_len_chk;
alter table public.reports validate constraint reports_summary_len_chk;
alter table public.reports validate constraint reports_content_len_chk;
alter table public.recommendations validate constraint recommendations_action_len_chk;
alter table public.public_analyses validate constraint public_analyses_summary_len_chk;
alter table public.audit_log validate constraint audit_log_detail_size_chk;
