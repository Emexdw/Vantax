-- Vantax: security hardening and private direct-message foundation.
-- Apply AFTER the baseline schema supplied by the project owner.
-- Chat design: text-only 1:1 conversations; mutual-follow required to start;
-- either participant can block the other. Messages are immutable and append-only.

begin;

-- ---------------------------------------------------------------------
-- Restrict privileged RPC execution and make view increments non-repeatable
-- for the same signed-in account on the same UTC day.
-- ---------------------------------------------------------------------
create table if not exists public.post_views (
  post_id uuid not null references public.posts(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  viewed_on date not null default (timezone('utc', now()))::date,
  created_at timestamptz not null default now(),
  primary key (post_id, user_id, viewed_on)
);
alter table public.post_views enable row level security;
revoke all on public.post_views from public, anon, authenticated;

create or replace function public.increment_views(target uuid) returns void
language plpgsql security definer set search_path = '' as $$
declare
  inserted_count integer;
begin
  if auth.uid() is null then
    raise exception 'Authentication required' using errcode = '28000';
  end if;
  if target is null then
    raise exception 'A post id is required' using errcode = '22023';
  end if;

  insert into public.post_views (post_id, user_id)
  select p.id, auth.uid()
  from public.posts p
  where p.id = target
  on conflict do nothing;

  get diagnostics inserted_count = row_count;
  if inserted_count = 1 then
    update public.posts set views_count = views_count + 1 where id = target;
  end if;
end;
$$;
revoke all on function public.increment_views(uuid) from public, anon;
grant execute on function public.increment_views(uuid) to authenticated;

-- Definer RPCs must not be callable anonymously or through the default PUBLIC grant.
revoke all on function public.my_activity() from public, anon;
grant execute on function public.my_activity() to authenticated;
revoke all on function public.trending_tags(integer) from public, anon;
grant execute on function public.trending_tags(integer) to authenticated;
revoke all on function public.suggested_profiles(integer) from public, anon;
grant execute on function public.suggested_profiles(integer) to authenticated;

-- ---------------------------------------------------------------------
-- Direct messages. Conversation membership, not client-supplied IDs alone,
-- controls visibility. A client cannot add members or create arbitrary threads.
-- ---------------------------------------------------------------------
create table public.conversations (
  id uuid primary key default gen_random_uuid(),
  direct_key text not null unique,
  created_at timestamptz not null default now()
);

create table public.conversation_members (
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  joined_at timestamptz not null default now(),
  primary key (conversation_id, user_id)
);
create index conversation_members_user_idx
  on public.conversation_members (user_id, conversation_id);

create table public.messages (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  sender_id uuid not null references public.profiles(id) on delete cascade,
  body text not null check (char_length(btrim(body)) between 1 and 4000),
  created_at timestamptz not null default now()
);
create index messages_conversation_created_idx
  on public.messages (conversation_id, created_at desc);

create table public.user_blocks (
  blocker_id uuid not null references public.profiles(id) on delete cascade,
  blocked_id uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (blocker_id, blocked_id),
  check (blocker_id <> blocked_id)
);

alter table public.conversations enable row level security;
alter table public.conversation_members enable row level security;
alter table public.messages enable row level security;
alter table public.user_blocks enable row level security;

-- Helpers run with a fixed, empty search_path and expose only a boolean result.
create or replace function public.is_conversation_member(target_conversation uuid)
returns boolean
language sql stable security definer set search_path = '' as $$
  select auth.uid() is not null and exists (
    select 1 from public.conversation_members cm
    where cm.conversation_id = target_conversation and cm.user_id = auth.uid()
  );
$$;
revoke all on function public.is_conversation_member(uuid) from public, anon;
grant execute on function public.is_conversation_member(uuid) to authenticated;

create or replace function public.can_send_message(target_conversation uuid)
returns boolean
language sql stable security definer set search_path = '' as $$
  select auth.uid() is not null
    and exists (
      select 1
      from public.conversation_members mine
      where mine.conversation_id = target_conversation
        and mine.user_id = auth.uid()
    )
    and not exists (
      select 1
      from public.conversation_members other_member
      join public.user_blocks b
        on (b.blocker_id = other_member.user_id and b.blocked_id = auth.uid())
        or (b.blocker_id = auth.uid() and b.blocked_id = other_member.user_id)
      where other_member.conversation_id = target_conversation
        and other_member.user_id <> auth.uid()
    );
$$;
revoke all on function public.can_send_message(uuid) from public, anon;
grant execute on function public.can_send_message(uuid) to authenticated;

-- Only this RPC may create a conversation or its member rows. Requiring a
-- mutual follow limits unsolicited contact; the unique key makes creation safe
-- when both clients attempt to open the same direct conversation concurrently.
create or replace function public.create_direct_conversation(target_user uuid)
returns uuid
language plpgsql security definer set search_path = '' as $$
declare
  caller uuid := auth.uid();
  first_user text;
  second_user text;
  conversation uuid;
begin
  if caller is null then
    raise exception 'Authentication required' using errcode = '28000';
  end if;
  if target_user is null or target_user = caller then
    raise exception 'Choose another user' using errcode = '22023';
  end if;
  if not exists (select 1 from public.profiles p where p.id = target_user) then
    raise exception 'User not found' using errcode = '22023';
  end if;
  if exists (
    select 1 from public.user_blocks b
    where (b.blocker_id = caller and b.blocked_id = target_user)
       or (b.blocker_id = target_user and b.blocked_id = caller)
  ) then
    raise exception 'Conversation unavailable' using errcode = '42501';
  end if;
  if not exists (
    select 1 from public.follows f
    where f.follower_id = caller and f.following_id = target_user
  ) or not exists (
    select 1 from public.follows f
    where f.follower_id = target_user and f.following_id = caller
  ) then
    raise exception 'Mutual follow required to start a conversation' using errcode = '42501';
  end if;

  if caller::text < target_user::text then
    first_user := caller::text;
    second_user := target_user::text;
  else
    first_user := target_user::text;
    second_user := caller::text;
  end if;

  insert into public.conversations (direct_key)
  values (first_user || ':' || second_user)
  on conflict (direct_key) do update set direct_key = excluded.direct_key
  returning id into conversation;

  insert into public.conversation_members (conversation_id, user_id)
  values (conversation, caller), (conversation, target_user)
  on conflict do nothing;

  return conversation;
end;
$$;
revoke all on function public.create_direct_conversation(uuid) from public, anon;
grant execute on function public.create_direct_conversation(uuid) to authenticated;

create policy conversations_read_member on public.conversations
  for select to authenticated using (public.is_conversation_member(id));
create policy conversation_members_read_member on public.conversation_members
  for select to authenticated using (public.is_conversation_member(conversation_id));
create policy messages_read_member on public.messages
  for select to authenticated using (public.is_conversation_member(conversation_id));
create policy messages_insert_member on public.messages
  for insert to authenticated
  with check (sender_id = auth.uid() and public.can_send_message(conversation_id));

create policy user_blocks_read_own on public.user_blocks
  for select to authenticated using (blocker_id = auth.uid());
create policy user_blocks_insert_own on public.user_blocks
  for insert to authenticated with check (blocker_id = auth.uid());
create policy user_blocks_delete_own on public.user_blocks
  for delete to authenticated using (blocker_id = auth.uid());

-- No client-side conversation/member writes, message edits, or message deletion.
revoke all on public.conversations, public.conversation_members, public.messages, public.user_blocks
  from public, anon, authenticated;
grant select on public.conversations, public.conversation_members to authenticated;
grant select, insert on public.messages to authenticated;
grant select, insert, delete on public.user_blocks to authenticated;

-- Realtime is optional in local/test environments; add messages only if the
-- Supabase publication exists and the table is not already registered.
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (
       select 1 from pg_publication_tables
       where pubname = 'supabase_realtime'
         and schemaname = 'public'
         and tablename = 'messages'
     ) then
    alter publication supabase_realtime add table public.messages;
  end if;
end;
$$;

commit;
