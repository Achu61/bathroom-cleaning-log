-- Bathroom Cleaning Log: run this ONCE in Supabase -> SQL Editor -> New query -> Run
create extension if not exists pgcrypto with schema extensions;

create table if not exists bathrooms(id text primary key, name text not null, blk text not null);
create table if not exists staff(id text primary key, name text not null, role text not null check (role in ('admin','cleaner')), pw text not null, created timestamptz not null default now());
create table if not exists sessions(token text primary key, uid text not null references staff(id) on delete cascade, created timestamptz not null default now());
create table if not exists logs(seq bigserial primary key, bid text not null, bname text not null, blk text not null, uid text not null, uname text not null, status text not null check (status in ('cleaned','not cleaned')), note text not null default '', ts timestamptz not null default now());
create index if not exists logs_ts on logs(ts desc);

-- Lock the tables: nobody can read them directly, only through the functions below.
alter table bathrooms enable row level security;
alter table staff enable row level security;
alter table sessions enable row level security;
alter table logs enable row level security;
revoke all on bathrooms, staff, sessions, logs from anon, authenticated;

-- Bathroom list (edit names here if needed)
insert into bathrooms(id,name,blk) values
('N-01','Ground – Central Toilet','New Block'),
('N-02','2nd NHDU','New Block'),
('N-03','Cardiac Ward','New Block'),
('N-04','Dialysis','New Block'),
('N-05','5 B wing – Cubicle 2525–29','New Block'),
('N-06','5 B wing – Cubicle 2530–34','New Block'),
('N-07','5 B wing – Cubicle 2545–49','New Block'),
('N-08','6 B wing – Cubicle A','New Block'),
('N-09','6 B wing – Cubicle B','New Block'),
('N-10','6 B wing – Cubicle C','New Block'),
('N-11','6 B wing – Cubicle D','New Block'),
('N-12','6 B wing – Cubicle E','New Block'),
('N-13','6 B wing – Cubicle F','New Block'),
('N-14','7 B wing – Cubicle A','New Block'),
('N-15','7 B wing – Cubicle B','New Block'),
('N-16','7 B wing – Cubicle C','New Block'),
('N-17','7 B wing – Cubicle D','New Block'),
('N-18','7 B wing – Cubicle E','New Block'),
('N-19','7 B wing – Cubicle F','New Block'),
('O-01','Ground – Central','Old Block'),
('O-02','ED near Pharmacy','Old Block'),
('O-03','ED inside','Old Block'),
('O-04','Acute 1','Old Block'),
('O-05','Oncology Ground','Old Block'),
('O-06','Oncology First','Old Block'),
('O-07','Khaleej Ground','Old Block'),
('O-08','Daycare 1','Old Block'),
('O-09','Daycare 2','Old Block'),
('O-10','Nuclear','Old Block'),
('O-11','1st Floor – Central','Old Block'),
('O-12','1st Floor – Lab','Old Block'),
('O-13','Gynec','Old Block'),
('O-14','Counter 1','Old Block'),
('O-15','Ortho','Old Block'),
('O-16','ENT','Old Block'),
('O-17','Xray','Old Block'),
('O-18','Procedure OPD','Old Block'),
('O-19','USG','Old Block'),
('O-20','Counter 5','Old Block'),
('O-21','2nd Floor – Central','Old Block'),
('O-22','2nd Floor – Lab','Old Block'),
('O-23','Administration','Old Block'),
('O-24','Cardiac OP','Old Block'),
('O-25','3rd Floor – Central Toilet','Old Block'),
('O-26','4th – Colonoscopy','Old Block'),
('O-27','4th – Day surgery','Old Block')
on conflict (id) do update set name=excluded.name, blk=excluded.blk;

-- ===== Functions (the only way the website talks to the data) =====
create or replace function _who(t text) returns staff language sql security definer set search_path = public, extensions as $$
  select s.* from staff s join sessions x on x.uid = s.id where x.token = t and x.created > now() - interval '30 days' limit 1
$$;
revoke execute on function _who(text) from public, anon, authenticated;

create or replace function app_bathrooms() returns json language sql security definer set search_path = public, extensions as $$
  select coalesce(json_agg(b order by b.id), '[]'::json) from bathrooms b
$$;
create or replace function app_status() returns boolean language sql security definer set search_path = public, extensions as $$
  select not exists (select 1 from staff)
$$;

create or replace function app_setup(i text, n text, p text) returns json language plpgsql security definer set search_path = public, extensions as $$
declare u text := lower(trim(i)); nm text := coalesce(nullif(trim(n), ''), lower(trim(i))); tk text;
begin
  if exists (select 1 from staff) then raise exception 'Already set up.'; end if;
  if u !~ '^[a-z0-9._-]{3,}$' or length(coalesce(p,'')) < 6 then raise exception 'ID needs 3+ letters or digits; password 6+ characters.'; end if;
  insert into staff(id,name,role,pw) values (u, nm, 'admin', crypt(p, gen_salt('bf')));
  tk := encode(gen_random_bytes(32), 'hex');
  insert into sessions(token,uid) values (tk, u);
  return json_build_object('token', tk, 'id', u, 'name', nm, 'role', 'admin');
end $$;

create or replace function app_login(i text, p text) returns json language plpgsql security definer set search_path = public, extensions as $$
declare s staff; tk text;
begin
  select * into s from staff where id = lower(trim(i));
  if s.id is null or s.pw <> crypt(coalesce(p,''), s.pw) then perform pg_sleep(1); raise exception 'Wrong ID or password.'; end if;
  delete from sessions where created < now() - interval '30 days';
  tk := encode(gen_random_bytes(32), 'hex');
  insert into sessions(token,uid) values (tk, s.id);
  return json_build_object('token', tk, 'id', s.id, 'name', s.name, 'role', s.role);
end $$;

create or replace function app_me(t text) returns json language plpgsql security definer set search_path = public, extensions as $$
declare me staff;
begin
  select * into me from _who(t);
  if me.id is null then raise exception 'Please sign in.'; end if;
  return json_build_object('id', me.id, 'name', me.name, 'role', me.role);
end $$;

create or replace function app_logout(t text) returns void language sql security definer set search_path = public, extensions as $$
  delete from sessions where token = t
$$;

-- Date and time come from the database server clock, not the phone.
create or replace function app_log(t text, b text, s text, n text) returns json language plpgsql security definer set search_path = public, extensions as $$
declare me staff; bt bathrooms; tsv timestamptz;
begin
  select * into me from _who(t);
  if me.id is null then raise exception 'Please sign in.'; end if;
  select * into bt from bathrooms where id = b;
  if bt.id is null then raise exception 'Unknown bathroom.'; end if;
  if s not in ('cleaned','not cleaned') then raise exception 'Invalid status.'; end if;
  insert into logs(bid,bname,blk,uid,uname,status,note) values (bt.id, bt.name, bt.blk, me.id, me.name, s, left(coalesce(n,''), 300)) returning ts into tsv;
  return json_build_object('bname', bt.name, 'ts', tsv);
end $$;

create or replace function app_logs(t text) returns json language plpgsql security definer set search_path = public, extensions as $$
declare me staff;
begin
  select * into me from _who(t);
  if me.id is null then raise exception 'Please sign in.'; end if;
  if me.role = 'admin' then
    return coalesce((select json_agg(x) from (select bid,bname,blk,uid,uname,status,note,ts from logs order by ts desc limit 5000) x), '[]'::json);
  end if;
  return coalesce((select json_agg(x) from (select bid,bname,blk,uid,uname,status,note,ts from logs where uid = me.id order by ts desc limit 8) x), '[]'::json);
end $$;

create or replace function app_last(t text) returns json language plpgsql security definer set search_path = public, extensions as $$
declare me staff;
begin
  select * into me from _who(t);
  if me.id is null or me.role <> 'admin' then raise exception 'Admin only.'; end if;
  return coalesce((select json_agg(x) from (select distinct on (bid) bid,bname,blk,uid,uname,status,note,ts from logs order by bid, ts desc) x), '[]'::json);
end $$;

create or replace function app_users(t text) returns json language plpgsql security definer set search_path = public, extensions as $$
declare me staff;
begin
  select * into me from _who(t);
  if me.id is null or me.role <> 'admin' then raise exception 'Admin only.'; end if;
  return coalesce((select json_agg(x) from (select id,name,role from staff order by id) x), '[]'::json);
end $$;

create or replace function app_add_user(t text, i text, n text, p text, r text) returns void language plpgsql security definer set search_path = public, extensions as $$
declare me staff; u text := lower(trim(i));
begin
  select * into me from _who(t);
  if me.id is null or me.role <> 'admin' then raise exception 'Admin only.'; end if;
  if u !~ '^[a-z0-9._-]{3,}$' or length(coalesce(p,'')) < 6 or r not in ('cleaner','admin') then raise exception 'ID: 3+ letters or digits (no spaces). Password: 6+ characters.'; end if;
  if exists (select 1 from staff where id = u) then raise exception 'That ID is already used.'; end if;
  insert into staff(id,name,role,pw) values (u, coalesce(nullif(trim(n), ''), u), r, crypt(p, gen_salt('bf')));
end $$;

create or replace function app_set_pw(t text, i text, p text) returns void language plpgsql security definer set search_path = public, extensions as $$
declare me staff;
begin
  select * into me from _who(t);
  if me.id is null or me.role <> 'admin' then raise exception 'Admin only.'; end if;
  if length(coalesce(p,'')) < 6 then raise exception 'Password: 6+ characters.'; end if;
  update staff set pw = crypt(p, gen_salt('bf')) where id = i;
  delete from sessions where uid = i;
end $$;

create or replace function app_del_user(t text, i text) returns void language plpgsql security definer set search_path = public, extensions as $$
declare me staff;
begin
  select * into me from _who(t);
  if me.id is null or me.role <> 'admin' then raise exception 'Admin only.'; end if;
  if i = me.id then raise exception 'You cannot remove yourself.'; end if;
  delete from staff where id = i;
end $$;

grant execute on function app_bathrooms(), app_status(), app_setup(text,text,text), app_login(text,text), app_me(text), app_logout(text),
  app_log(text,text,text,text), app_logs(text), app_last(text), app_users(text), app_add_user(text,text,text,text,text), app_set_pw(text,text,text), app_del_user(text,text) to anon;
