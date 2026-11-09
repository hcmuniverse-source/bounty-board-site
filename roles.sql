-- Roles: poster (can post tasks), worker (can take jobs and submit), both.
-- Existing people become 'both' so nothing breaks; anyone added later starts as 'worker'.
alter table profiles add column if not exists role text not null default 'both' check (role in ('poster','worker','both'));
alter table profiles alter column role set default 'worker';

drop policy if exists p_tasks_i on tasks;
create policy p_tasks_i on tasks for insert to authenticated with check (poster_id=auth.uid()
 and exists(select 1 from profiles p where p.id=auth.uid() and p.role in ('poster','both')));

drop policy if exists p_claims_i on claims;
create policy p_claims_i on claims for insert to authenticated with check (worker_id=auth.uid()
 and exists(select 1 from tasks t where t.id=task_id and t.status='open' and t.poster_id<>auth.uid())
 and exists(select 1 from profiles p where p.id=auth.uid() and p.role in ('worker','both')));

drop policy if exists p_subs_i on submissions;
create policy p_subs_i on submissions for insert to authenticated with check (worker_id=auth.uid() and status='pending'
 and exists(select 1 from tasks t where t.id=task_id and t.status='open' and t.poster_id<>auth.uid())
 and exists(select 1 from profiles p where p.id=auth.uid() and p.role in ('worker','both')));
