create table public.domains (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users (id),
  name varchar(253) not null,
  verification_method varchar(8) not null,
  verification_token varchar(128) not null
    default ('safeit-verification=' || replace(gen_random_uuid()::text, '-', '')),
  status varchar(10) not null default 'pending',
  verified_at timestamptz,
  constraint domains_user_name_key unique (user_id, name),
  constraint domains_name_chk check (
    name = lower(name)
    and name ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'
  ),
  constraint domains_method_chk check (verification_method in ('dns_txt', 'file')),
  constraint domains_status_chk check (status in ('pending', 'verified', 'failed')),
  constraint domains_verified_at_chk check ((status = 'verified') = (verified_at is not null))
);

create unique index domains_verified_name_key
  on public.domains (name)
  where status = 'verified';

create table public.scans (
  id uuid primary key default gen_random_uuid(),
  domain_id uuid not null references public.domains (id) on delete cascade,
  started_by uuid not null references public.users (id),
  type varchar(8) not null,
  status varchar(8) not null default 'queued',
  celery_task_id varchar(64),
  created_at timestamptz not null default now(),
  started_at timestamptz,
  finished_at timestamptz,
  constraint scans_id_domain_key unique (id, domain_id),
  constraint scans_type_chk check (type in ('recon', 'tests')),
  constraint scans_status_chk check (status in ('queued', 'running', 'done', 'failed')),
  constraint scans_finished_chk check (
    finished_at is null or started_at is null or finished_at >= started_at
  )
);

create table public.assets (
  id uuid primary key default gen_random_uuid(),
  domain_id uuid not null,
  scan_id uuid not null,
  kind varchar(9) not null,
  value varchar(255) not null,
  in_scope boolean not null default false,
  discovered_at timestamptz not null default now(),
  constraint assets_scan_domain_fkey foreign key (scan_id, domain_id)
    references public.scans (id, domain_id) on delete cascade,
  constraint assets_domain_kind_value_key unique (domain_id, kind, value),
  constraint assets_kind_chk check (kind in ('subdomain', 'ip')),
  constraint assets_value_chk check (value = lower(btrim(value)) and length(value) > 0)
);

create table public.services (
  id uuid primary key default gen_random_uuid(),
  asset_id uuid not null references public.assets (id) on delete cascade,
  port integer not null,
  protocol varchar(3) not null,
  name varchar(64),
  version varchar(128),
  banner text,
  constraint services_asset_port_proto_key unique (asset_id, port, protocol),
  constraint services_port_chk check (port between 1 and 65535),
  constraint services_protocol_chk check (protocol in ('tcp', 'udp'))
);

create table public.endpoints (
  id uuid primary key default gen_random_uuid(),
  asset_id uuid not null references public.assets (id) on delete cascade,
  url varchar(2048) not null,
  http_status integer,
  technologies jsonb not null default '[]'::jsonb,
  whitelisted boolean not null default false,
  constraint endpoints_asset_url_key unique (asset_id, url),
  constraint endpoints_url_chk check (url ~ '^https?://'),
  constraint endpoints_http_status_chk check (http_status is null or http_status between 100 and 599)
);
