-- Pawsenger Tag — Supabase schema (privacy-by-design, red-teamed 2026-06-25).
-- Project ref: zkvyxlofetpwehfddyvl
-- Apply: paste in Supabase SQL Editor → Run, OR `psql "$DB_URL" -f migration.sql`.
--
-- THREAT MODEL: the found-pet page is PUBLIC — any finder opens it with the ANON (publishable)
-- key. The owner's email/phone/name must NEVER reach that browser, and the catalog of pets must
-- not be bulk-dumpable. So anon gets ZERO table/view grants; its ONLY surface is three
-- security-definer RPCs:
--   get_pet(tag_id)      -> safe columns for ONE tag (no bulk enumeration, owner contact never selected)
--   log_scan(tag_id,msg) -> append a scan event (FK-guarded, no tag-existence oracle)
--   register_pet(...)    -> one-shot claim of a physical tag (claimed-guard blocks hijack, attempt limiter)
-- pet_profiles (with owner_*) is invisible to anon: no grant, no view, not even in its OpenAPI.

create extension if not exists pgcrypto;

-- ── tables ───────────────────────────────────────────────────────────────────
create table if not exists public.tags (
  id             text primary key,                       -- short code printed on the physical tag
  claim_code     text not null,                          -- secret on the tag card; gates registration
  claimed        boolean not null default false,
  claim_attempts int not null default 0,                 -- brute-force lockout counter
  created_at     timestamptz not null default now()
);

create table if not exists public.pet_profiles (
  tag_id       text primary key references public.tags(id) on delete cascade,
  pet_name     text not null,
  emoji        text default '🐾',
  photo_url    text,
  public_note  text,                                     -- shown to finder (safe)
  owner_name   text,                                     -- PRIVATE
  owner_email  text,                                     -- PRIVATE
  owner_phone  text,                                     -- PRIVATE
  lost_mode    boolean not null default false,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

create table if not exists public.scan_events (
  id             uuid primary key default gen_random_uuid(),
  tag_id         text references public.tags(id) on delete cascade,
  scanned_at     timestamptz not null default now(),
  finder_message text
);
create index if not exists scan_events_tag_idx on public.scan_events(tag_id, scanned_at desc);

-- ── lock base tables (RLS on, no policies => invisible to anon) ────────────────
alter table public.tags          enable row level security;
alter table public.pet_profiles  enable row level security;
alter table public.scan_events   enable row level security;

-- ── RPC: read ONE pet's safe fields (no bulk dump, owner_* never projected) ────
create or replace function public.get_pet(p_tag_id text)
returns table(tag_id text, pet_name text, emoji text, photo_url text, public_note text, lost_mode boolean)
language sql security definer set search_path = public as $$
  select tag_id, pet_name, emoji, photo_url, public_note, lost_mode
  from public.pet_profiles where tag_id = p_tag_id;
$$;

-- ── RPC: log a scan (FK-guarded; invalid tag silently ignored = no oracle) ─────
create or replace function public.log_scan(p_tag_id text, p_finder_message text default null)
returns void language plpgsql security definer set search_path = public as $$
begin
  insert into public.scan_events(tag_id, finder_message)
  values (p_tag_id, left(coalesce(p_finder_message, ''), 500));
exception when foreign_key_violation then
  null;  -- unknown tag: swallow, don't reveal existence
end $$;

-- ── RPC: owner self-registers a tag (one-shot; claimed-guard + attempt limiter) ─
create or replace function public.register_pet(
  p_tag_id text, p_claim_code text, p_pet_name text,
  p_public_note text default null, p_emoji text default '🐾',
  p_owner_name text default null, p_owner_email text default null, p_owner_phone text default null
) returns text language plpgsql security definer set search_path = public as $$
declare v_code text; v_claimed boolean; v_attempts int;
begin
  select claim_code, claimed, claim_attempts into v_code, v_claimed, v_attempts
  from public.tags where id = p_tag_id;
  if v_code is null then return 'no_such_tag'; end if;
  if v_attempts >= 10 then return 'locked'; end if;          -- brute-force lockout
  if v_code <> p_claim_code then
    update public.tags set claim_attempts = claim_attempts + 1 where id = p_tag_id;
    return 'bad_claim_code';
  end if;
  if v_claimed then return 'already_claimed'; end if;         -- HIJACK GUARD: no overwrite of a live tag
  if coalesce(trim(p_pet_name),'') = '' then return 'name_required'; end if;

  insert into public.pet_profiles(tag_id, pet_name, emoji, public_note, owner_name, owner_email, owner_phone, updated_at)
  values (p_tag_id, p_pet_name, coalesce(nullif(trim(p_emoji),''),'🐾'), p_public_note,
          p_owner_name, p_owner_email, p_owner_phone, now());
  update public.tags set claimed = true, claim_attempts = 0 where id = p_tag_id;
  return 'ok';
end $$;
-- NOTE: registration is one-shot per tag. Owner edits/transfer should later go through an
-- email-token flow (token sent to the stored owner_email), NOT the reusable claim_code.

-- expose ONLY the three RPCs to anon (no table/view grants anywhere)
revoke all on function public.get_pet(text) from public;
revoke all on function public.log_scan(text, text) from public;
revoke all on function public.register_pet(text, text, text, text, text, text, text, text) from public;
grant execute on function public.get_pet(text)   to anon, authenticated;
grant execute on function public.log_scan(text, text) to anon, authenticated;
grant execute on function public.register_pet(text, text, text, text, text, text, text, text) to anon, authenticated;

-- ── seed two demo tags (already claimed, so the hijack guard also protects them) ─
insert into public.tags(id, claim_code, claimed) values
  ('BUDDY01','demo-buddy', true),
  ('MILO22','demo-milo', true)
on conflict (id) do nothing;

insert into public.pet_profiles(tag_id, pet_name, emoji, public_note, owner_name, owner_email) values
  ('BUDDY01','Buddy','🐶','Friendly golden retriever. A little shy with strangers but loves treats.','Demo Owner','demo@pawsenger.example'),
  ('MILO22','Milo','🐱','Orange tabby cat, indoor. Please don''t chase — just message me!','Demo Owner','demo@pawsenger.example')
on conflict (tag_id) do nothing;
