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
    execute format('drop policy if exists deny_client_roles on public.%I', t);
    execute format('alter table public.%I no force row level security', t);
  end loop;
end
$$;

alter table public.users
  drop constraint if exists users_email_len_chk,
  drop constraint if exists users_password_hash_len_chk,
  drop constraint if exists users_totp_secret_len_chk;
alter table public.services drop constraint if exists services_banner_len_chk;
alter table public.llm_decisions drop constraint if exists llm_decisions_justification_len_chk;
alter table public.findings drop constraint if exists findings_fp_justification_len_chk;
alter table public.reports
  drop constraint if exists reports_summary_len_chk,
  drop constraint if exists reports_content_len_chk;
alter table public.recommendations drop constraint if exists recommendations_action_len_chk;
alter table public.public_analyses drop constraint if exists public_analyses_summary_len_chk;
alter table public.audit_log drop constraint if exists audit_log_detail_size_chk;
