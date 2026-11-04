create table public.allowed_tools (
  id uuid primary key default gen_random_uuid(),
  name varchar(32) not null,
  allowed_params jsonb not null default '{}'::jsonb,
  active boolean not null default true,
  constraint allowed_tools_name_key unique (name),
  constraint allowed_tools_name_chk check (name ~ '^[a-z0-9_-]+$')
);

create table public.cve_catalog (
  cve_id varchar(20) primary key,
  cvss_score numeric(3, 1),
  cvss_vector varchar(128),
  epss_score numeric(6, 5),
  in_cisa_kev boolean not null default false,
  synced_at timestamptz not null default now(),
  constraint cve_catalog_id_chk check (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
  constraint cve_catalog_cvss_chk check (cvss_score is null or cvss_score between 0 and 10),
  constraint cve_catalog_epss_chk check (epss_score is null or epss_score between 0 and 1)
);

create table public.llm_decisions (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid not null references public.scans (id) on delete cascade,
  kind varchar(14) not null,
  model varchar(100) not null,
  input_hash varchar(64) not null,
  output_json jsonb not null,
  validated boolean not null default false,
  justification text,
  created_at timestamptz not null default now(),
  constraint llm_decisions_id_scan_key unique (id, scan_id),
  constraint llm_decisions_kind_chk check (kind in ('plan', 'correlation', 'false_positive', 'report'))
);

create table public.test_runs (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid not null references public.scans (id) on delete cascade,
  endpoint_id uuid not null references public.endpoints (id) on delete cascade,
  tool_id uuid not null references public.allowed_tools (id),
  decision_id uuid,
  params jsonb not null default '{}'::jsonb,
  status varchar(8) not null default 'queued',
  result_enc bytea,
  started_at timestamptz,
  finished_at timestamptz,
  constraint test_runs_id_endpoint_key unique (id, endpoint_id),
  constraint test_runs_decision_scan_fkey foreign key (decision_id, scan_id)
    references public.llm_decisions (id, scan_id),
  constraint test_runs_status_chk check (status in ('queued', 'running', 'done', 'failed')),
  constraint test_runs_finished_chk check (
    finished_at is null or started_at is null or finished_at >= started_at
  )
);

create table public.findings (
  id uuid primary key default gen_random_uuid(),
  test_run_id uuid not null,
  endpoint_id uuid not null,
  decision_id uuid references public.llm_decisions (id) on delete set null,
  title varchar(255) not null,
  severity varchar(8) not null,
  priority_score numeric(5, 2),
  is_false_positive boolean not null default false,
  fp_justification text,
  remediation_status varchar(12) not null default 'open',
  evidence_enc bytea,
  detected_at timestamptz not null default now(),
  constraint findings_test_run_endpoint_fkey foreign key (test_run_id, endpoint_id)
    references public.test_runs (id, endpoint_id) on delete cascade,
  constraint findings_severity_chk check (severity in ('info', 'low', 'medium', 'high', 'critical')),
  constraint findings_priority_chk check (priority_score is null or priority_score between 0 and 100),
  constraint findings_remediation_chk check (remediation_status in ('open', 'in_progress', 'fixed')),
  constraint findings_fp_justification_chk check (
    not is_false_positive or nullif(btrim(fp_justification), '') is not null
  )
);

create table public.finding_cves (
  finding_id uuid not null references public.findings (id) on delete cascade,
  cve_id varchar(20) not null references public.cve_catalog (cve_id),
  primary key (finding_id, cve_id)
);

create table public.reports (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid not null,
  decision_id uuid,
  summary text not null,
  content text not null,
  created_at timestamptz not null default now(),
  constraint reports_scan_key unique (scan_id),
  constraint reports_decision_key unique (decision_id),
  constraint reports_scan_fkey foreign key (scan_id)
    references public.scans (id) on delete cascade,
  constraint reports_decision_scan_fkey foreign key (decision_id, scan_id)
    references public.llm_decisions (id, scan_id)
);

create table public.recommendations (
  id uuid primary key default gen_random_uuid(),
  report_id uuid not null references public.reports (id) on delete cascade,
  finding_id uuid not null references public.findings (id) on delete cascade,
  priority integer not null,
  action text not null,
  status varchar(12) not null default 'pending',
  constraint recommendations_priority_chk check (priority >= 1),
  constraint recommendations_status_chk check (status in ('pending', 'in_progress', 'done', 'dismissed'))
);
