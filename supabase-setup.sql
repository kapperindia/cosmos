-- Run once in Supabase: SQL Editor -> New query -> paste -> Run
create table if not exists member_files (
  id bigint generated always as identity primary key,
  filename text not null,
  version int not null,
  content_hash text not null,
  uploaded_at timestamptz not null default now(),
  row_count int not null default 0,
  rejected_count int not null default 0,
  storage_path text,              -- where the original file is kept in Storage
  unique (filename, version)
);
create table if not exists member_file_rows (
  id bigint generated always as identity primary key,
  file_id bigint not null references member_files(id) on delete cascade,
  mobile text not null,            -- key field
  member_id text, name text, email text, category text, eligible boolean default true,
  unique (file_id, mobile)
);
create index if not exists member_file_rows_mobile_idx on member_file_rows(mobile);

-- Saves one upload; same filename => next version number
create or replace function save_member_file(p_filename text, p_hash text, p_rows jsonb, p_rejected int)
returns table(file_id bigint, version int, uploaded_at timestamptz) language plpgsql as $$
declare v int; fid bigint; ts timestamptz;
begin
  perform pg_advisory_xact_lock(hashtext(p_filename));
  select coalesce(max(f.version),0)+1 into v from member_files f where f.filename = p_filename;
  insert into member_files(filename,version,content_hash,row_count,rejected_count)
    values (p_filename,v,p_hash,jsonb_array_length(p_rows),coalesce(p_rejected,0))
    returning id, member_files.uploaded_at into fid, ts;
  insert into member_file_rows(file_id,mobile,member_id,name,email,category,eligible)
    select fid, r->>'mobile', r->>'member_id', r->>'name', r->>'email', r->>'category', coalesce((r->>'eligible')::boolean,true)
    from jsonb_array_elements(p_rows) r;
  return query select fid, v, ts;
end $$;

-- Only the server (service key) may read/write
alter table member_files enable row level security;
alter table member_file_rows enable row level security;
revoke all on function save_member_file from public, anon, authenticated;

alter table member_files add column if not exists storage_path text;
-- Private Storage buckets: original upload files, and database snapshots
insert into storage.buckets (id, name, public) values ('member-files','member-files',false), ('backups','backups',false) on conflict (id) do nothing;
