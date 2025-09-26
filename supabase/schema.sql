-- Supabase schema for Argus Guardian

create table if not exists public.api_keys (
  id uuid primary key default gen_random_uuid(),
  key_hash text not null unique,
  owner_email text,
  status text not null default 'active',
  created_at timestamp with time zone default now()
);

create table if not exists public.logs (
  id uuid primary key default gen_random_uuid(),
  request_id text not null,
  api_key_id uuid references public.api_keys(id) on delete set null,
  risk_score int not null,
  threats jsonb not null default '[]'::jsonb,
  text_length int not null default 0,
  request_meta jsonb not null default '{}'::jsonb,
  created_at timestamp with time zone default now()
);

-- RLS
alter table public.api_keys enable row level security;
alter table public.logs enable row level security;

-- Policy: api_keys are only visible to their owner via email claim
do $$ begin
  create policy if not exists "api_keys_owner_read" on public.api_keys
  for select using (auth.jwt() ->> 'email' = owner_email);
exception when others then null; end $$;

-- Policy: logs visible where api_key belongs to the caller's email
do $$ begin
  create policy if not exists "logs_by_owner_read" on public.logs
  for select using (
    exists (
      select 1 from public.api_keys k
      where k.id = logs.api_key_id
        and k.owner_email = auth.jwt() ->> 'email'
    )
  );
exception when others then null; end $$;

-- Indexes
create index if not exists idx_logs_api_key_id on public.logs(api_key_id);
create index if not exists idx_logs_created_at on public.logs(created_at);



