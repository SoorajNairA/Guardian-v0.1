-- Supabase schema for Argus Guardian

create table if not exists public.api_keys (
  id uuid primary key default gen_random_uuid(),
  key_hash text not null unique,
  hash_type text not null default 'argon2', -- 'argon2' or 'legacy'
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

do $$ begin IF NOT EXISTS ( SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'api_keys' AND policyname = 'api_keys_owner_read' ) THEN CREATE POLICY api_keys_owner_read ON public.api_keys FOR SELECT USING (auth.jwt() ->> 'email' = owner_email); END IF; END; $$;

do $$ begin IF NOT EXISTS ( SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'logs' AND policyname = 'logs_by_owner_read' ) THEN CREATE POLICY logs_by_owner_read ON public.logs FOR SELECT USING ( EXISTS ( SELECT 1 FROM public.api_keys k WHERE k.id = logs.api_key_id AND k.owner_email = auth.jwt() ->> 'email' ) ); END IF; END; $$;

-- Indexes
create index if not exists idx_logs_api_key_id on public.logs(api_key_id);
create index if not exists idx_logs_created_at on public.logs(created_at);



