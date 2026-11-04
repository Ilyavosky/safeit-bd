create table public.users (
  id uuid primary key default gen_random_uuid(),
  email varchar(320) not null,
  password_hash text not null,
  role varchar(16) not null default 'viewer',
  totp_secret_enc text,
  mfa_enabled boolean not null default false,
  created_at timestamptz not null default now(),
  constraint users_email_key unique (email),
  constraint users_email_lower_chk check (email = lower(email)),
  constraint users_role_chk check (role in ('admin', 'analyst', 'viewer')),
  constraint users_mfa_secret_chk check (not mfa_enabled or totp_secret_enc is not null)
);

create table public.refresh_tokens (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users (id) on delete cascade,
  family_id uuid not null,
  token_hash varchar(128) not null,
  expires_at timestamptz not null,
  revoked_at timestamptz,
  replaced_by uuid references public.refresh_tokens (id) on delete set null,
  constraint refresh_tokens_token_hash_key unique (token_hash),
  constraint refresh_tokens_not_self_chk check (replaced_by is distinct from id)
);
