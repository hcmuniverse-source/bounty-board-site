-- Bounty Board schema. Paste into Supabase > SQL Editor > Run.
create table if not exists profiles(id uuid primary key references auth.users on delete cascade, name text);
insert into profiles(id,name) select id, split_part(email,'@',1) from auth.users on conflict do nothing;
create or replace function handle_new_user() returns trigger language plpgsql security definer set search_path=public as $$
begin insert into profiles(id,name) values(new.id, split_part(new.email,'@',1)) on conflict do nothing; return new; end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute function handle_new_user();

create table if not exists tasks(id uuid primary key default gen_random_uuid(), poster_id uuid not null default auth.uid() references profiles(id),
 title text not null, description text, file_path text, file_type text, bounty_amount text, bounty_method text, bounty_note text,
 status text not null default 'open', winner_id uuid, winner_sub uuid, created_at timestamptz default now());
create table if not exists claims(task_id uuid references tasks on delete cascade, worker_id uuid default auth.uid() references profiles(id), primary key(task_id,worker_id));
create table if not exists submissions(id uuid primary key default gen_random_uuid(), task_id uuid not null references tasks on delete cascade,
 worker_id uuid not null default auth.uid() references profiles(id), file_path text not null, file_type text, note text,
 status text not null default 'pending', rating int, comment text, created_at timestamptz default now());
create table if not exists payouts(submission_id uuid primary key references submissions on delete cascade, worker_id uuid not null default auth.uid(), details text);

alter table profiles enable row level security; alter table tasks enable row level security; alter table claims enable row level security;
alter table submissions enable row level security; alter table payouts enable row level security;

create policy p_profiles on profiles for select to authenticated using (true);
create policy p_tasks_r on tasks for select to authenticated using (true);
create policy p_tasks_i on tasks for insert to authenticated with check (poster_id=auth.uid());
create policy p_claims_r on claims for select to authenticated using (true);
create policy p_claims_i on claims for insert to authenticated with check (worker_id=auth.uid() and exists(select 1 from tasks t where t.id=task_id and t.status='open' and t.poster_id<>auth.uid()));
-- A worker sees their own work; the poster sees all work on their task; everyone sees work once accepted.
create policy p_subs_r on submissions for select to authenticated using (worker_id=auth.uid() or status='accepted'
 or exists(select 1 from tasks t where t.id=task_id and t.poster_id=auth.uid()));
create policy p_subs_i on submissions for insert to authenticated with check (worker_id=auth.uid() and status='pending'
 and exists(select 1 from tasks t where t.id=task_id and t.status='open' and t.poster_id<>auth.uid()));
create policy p_pay_r on payouts for select to authenticated using (worker_id=auth.uid()
 or exists(select 1 from submissions s join tasks t on t.id=s.task_id where s.id=submission_id and t.poster_id=auth.uid()));
create policy p_pay_i on payouts for insert to authenticated with check (worker_id=auth.uid() and exists(select 1 from submissions s where s.id=submission_id and s.worker_id=auth.uid()));

create or replace function review_submission(sid uuid, v text, r int, c text) returns void language plpgsql security definer set search_path=public as $$
begin
 if v not in ('accepted','rejected') or r<0 or r>10 then raise exception 'bad input'; end if;
 update submissions s set status=v, rating=r, comment=c where s.id=sid and exists(select 1 from tasks t where t.id=s.task_id and t.poster_id=auth.uid());
 if not found then raise exception 'not allowed'; end if;
end $$;
create or replace function close_task(tid uuid, sid uuid) returns void language plpgsql security definer set search_path=public as $$
begin
 update tasks t set status='closed', winner_sub=sid, winner_id=(select worker_id from submissions where id=sid)
  where t.id=tid and t.poster_id=auth.uid() and exists(select 1 from submissions where id=sid and task_id=tid and status='accepted');
 if not found then raise exception 'not allowed'; end if;
end $$;
create or replace function reopen_task(tid uuid) returns void language plpgsql security definer set search_path=public as $$
begin update tasks set status='open', winner_sub=null, winner_id=null where id=tid and poster_id=auth.uid(); if not found then raise exception 'not allowed'; end if; end $$;
revoke all on function review_submission(uuid,text,int,text), close_task(uuid,uuid), reopen_task(uuid) from public, anon;
grant execute on function review_submission(uuid,text,int,text), close_task(uuid,uuid), reopen_task(uuid) to authenticated;

-- Private file storage (not public). Files live under <user id>/...
insert into storage.buckets(id,name,public,file_size_limit) values('files','files',false,52428800) on conflict (id) do update set public=false;
create policy f_ins on storage.objects for insert to authenticated with check (bucket_id='files' and (storage.foldername(name))[1]=auth.uid()::text);
create policy f_sel on storage.objects for select to authenticated using (bucket_id='files' and (
 (storage.foldername(name))[1]=auth.uid()::text
 or exists(select 1 from public.tasks t where t.file_path=name)
 or exists(select 1 from public.submissions s where s.file_path=name)));  -- RLS above limits which submissions are visible
