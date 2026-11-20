create table public.public_analyses (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users (id),
  domain varchar(253) not null,
  status varchar(10) not null default 'queued',
  summary text,
  summary_model varchar(100),
  stats jsonb not null default '{}'::jsonb,
  error varchar(300),
  created_at timestamptz not null default now(),
  finished_at timestamptz,
  expires_at timestamptz not null,
  constraint public_analyses_domain_chk check (
    domain = lower(domain)
    and domain ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'
  ),
  constraint public_analyses_status_chk check (status in ('queued', 'running', 'done', 'failed')),
  constraint public_analyses_finished_chk check (
    (status in ('done', 'failed')) = (finished_at is not null)
  )
);

create index public_analyses_user_created_idx
  on public.public_analyses (user_id, created_at desc);

create index public_analyses_expires_idx
  on public.public_analyses (expires_at);

create unique index public_analyses_one_active_per_user_key
  on public.public_analyses (user_id)
  where status in ('queued', 'running');

create table public.public_analysis_hosts (
  id uuid primary key default gen_random_uuid(),
  analysis_id uuid not null references public.public_analyses (id) on delete cascade,
  host varchar(253) not null,
  kind varchar(16) not null,
  http_status integer,
  title varchar(200),
  technologies text[] not null default '{}',
  provider varchar(80),
  redirect_host varchar(253),
  security_headers text[] not null default '{}',
  tls_issuer varchar(120),
  tls_valid boolean,
  tls_valid_until timestamptz,
  constraint public_analysis_hosts_key unique (analysis_id, host),
  constraint public_analysis_hosts_kind_chk check (
    kind in ('web_app', 'api', 'mail', 'login_panel', 'docs', 'blog', 'redirect', 'no_service')
  )
);

create index public_analysis_hosts_analysis_idx
  on public.public_analysis_hosts (analysis_id);

alter table public.public_analyses enable row level security;
alter table public.public_analysis_hosts enable row level security;

revoke all on public.public_analyses from anon, authenticated;
revoke all on public.public_analysis_hosts from anon, authenticated;
