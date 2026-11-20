alter table public.users enable row level security;
alter table public.refresh_tokens enable row level security;
alter table public.domains enable row level security;
alter table public.scans enable row level security;
alter table public.assets enable row level security;
alter table public.services enable row level security;
alter table public.endpoints enable row level security;
alter table public.allowed_tools enable row level security;
alter table public.cve_catalog enable row level security;
alter table public.llm_decisions enable row level security;
alter table public.test_runs enable row level security;
alter table public.findings enable row level security;
alter table public.finding_cves enable row level security;
alter table public.reports enable row level security;
alter table public.recommendations enable row level security;
alter table public.audit_log enable row level security;

revoke all on all tables in schema public from anon, authenticated;
revoke all on all sequences in schema public from anon, authenticated;
revoke all on all functions in schema public from public, anon, authenticated;

alter default privileges in schema public revoke all on tables from anon, authenticated;
alter default privileges in schema public revoke all on sequences from anon, authenticated;
alter default privileges in schema public revoke all on functions from public, anon, authenticated;
