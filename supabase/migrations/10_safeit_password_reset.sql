create table public.password_reset_tokens (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users (id) on delete cascade,
  token_hash varchar(128) not null,
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now(),
  constraint password_reset_tokens_token_hash_key unique (token_hash),
  constraint password_reset_tokens_expiry_chk check (expires_at > created_at)
);

create index password_reset_tokens_user_id_idx
  on public.password_reset_tokens (user_id);

create index password_reset_tokens_expires_idx
  on public.password_reset_tokens (expires_at);

alter table public.password_reset_tokens enable row level security;

revoke all on public.password_reset_tokens from anon, authenticated;
