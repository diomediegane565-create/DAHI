create extension if not exists pgcrypto with schema extensions;

create table if not exists public.kv (
  key text primary key,
  value jsonb,
  updated_at timestamptz not null default now()
);
alter table public.kv enable row level security;

create table if not exists public.app_secrets (
  name text primary key,
  value text not null
);
alter table public.app_secrets enable row level security;

-- comptes des membres (le mot de passe n'est jamais stocké en clair : hash bcrypt)
create table if not exists public.member_accounts (
  uid uuid primary key default gen_random_uuid(),
  email text not null,
  pass_hash text not null,
  created_at timestamptz not null default now()
);
create unique index if not exists member_accounts_email_key on public.member_accounts (lower(email));
alter table public.member_accounts enable row level security;

create table if not exists public.member_sessions (
  token_hash text primary key,
  uid uuid not null references public.member_accounts(uid) on delete cascade,
  expires_at timestamptz not null default now() + interval '30 days'
);
alter table public.member_sessions enable row level security;

-- ---------- helpers (non exposés) ----------
create or replace function public._is_admin(p text) returns boolean
language sql stable security definer set search_path = public, extensions as $$
  select p is not null and exists (
    select 1 from public.app_secrets s where s.name = 'admin_hash' and s.value = crypt(p, s.value)
  );
$$;

create or replace function public._commission_name(p_idx int, p_code text) returns text
language sql stable security definer set search_path = public, extensions as $$
  select t.e->>'name'
  from public.kv k,
       lateral jsonb_array_elements(k.value) with ordinality as t(e, i)
  where k.key = 'commissions'
    and p_idx is not null and p_code is not null
    and t.i - 1 = p_idx
    and coalesce(t.e->>'code','') <> ''
    and t.e->>'code' = p_code;
$$;

create or replace function public._member_uid(p_token text) returns uuid
language sql stable security definer set search_path = public, extensions as $$
  select s.uid from public.member_sessions s
  where p_token is not null and s.expires_at > now()
    and s.token_hash = encode(digest(p_token, 'sha256'), 'hex');
$$;

create or replace function public._new_session(p_uid uuid) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare tok text := encode(gen_random_bytes(32), 'hex');
begin
  delete from public.member_sessions where expires_at < now();
  insert into public.member_sessions(token_hash, uid) values (encode(digest(tok, 'sha256'), 'hex'), p_uid);
  return tok;
end $$;

-- donne un matricule explicite (d'après la position) aux fiches qui n'en ont pas
create or replace function public._members_frozen(cur jsonb) returns jsonb
language sql immutable set search_path = public as $$
  select coalesce(jsonb_agg(
    case when coalesce(e->>'matricule','') = '' then e || jsonb_build_object('matricule', 'KKHA-' || lpad(i::text, 4, '0')) else e end
    order by i), '[]'::jsonb)
  from jsonb_array_elements(coalesce(cur, '[]'::jsonb)) with ordinality as t(e, i);
$$;

create or replace function public._check_new_account(p_email text, p_password text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if p_email is null or position('@' in p_email) < 2 or length(p_email) > 200 then raise exception 'EMAIL_REQUIRED'; end if;
  if p_password is null or length(p_password) < 6 then raise exception 'WEAK_PASSWORD'; end if;
  if exists (select 1 from public.member_accounts where lower(email) = lower(trim(p_email))) then raise exception 'EMAIL_EXISTS'; end if;
end $$;

create or replace function public._key_class(k text) returns text
language sql immutable set search_path = public as $$
  select case
    when k = 'adminPassword' then 'never'
    when k = 'memberCount' then 'count'
    when k = 'members' then 'members'
    when k = 'commissionSpace' then 'cspace'
    when k = 'commissions' then 'commissions'
    when k like 'memberPhoto\_%' then 'admin'
    when k like 'docFile\_%' or k like 'mediaFile\_%' then 'cfile'
    else 'public'
  end;
$$;

-- ---------- API ----------
-- kv_get change de signature (nouveau paramètre p_token) : on supprime l'ancienne version.
drop function if exists public.kv_get(text, text, int, text);
create or replace function public.kv_get(p_key text, p_admin text default null, p_cidx int default null, p_ccode text default null, p_token text default null)
returns jsonb language plpgsql stable security definer set search_path = public, extensions as $$
declare cls text := public._key_class(p_key); v jsonb; cname text; adm boolean; mem boolean;
begin
  if cls = 'never' then return null; end if;
  if cls = 'count' then
    return to_jsonb(coalesce(jsonb_array_length((select value from public.kv where key = 'members')), 0));
  end if;
  adm := public._is_admin(p_admin);
  mem := adm or public._member_uid(p_token) is not null;
  select value into v from public.kv where key = p_key;
  if cls = 'public' then
    -- tout le contenu du site est réservé aux membres connectés (la charte reste lisible pour s'inscrire)
    if mem or p_key = 'charte' then return v; end if;
    return null;
  end if;
  if adm then return v; end if;
  if v is null then return null; end if;
  if cls = 'commissions' then
    if not mem then return null; end if;
    return (select coalesce(jsonb_agg(e - 'code'), '[]'::jsonb) from jsonb_array_elements(v) e);
  end if;
  cname := public._commission_name(p_cidx, p_ccode);
  if cname is null then return null; end if;
  if cls = 'members' then
    return (select coalesce(jsonb_agg(jsonb_build_object('prenom', e->'prenom', 'nom', e->'nom', 'tel', e->'tel')), '[]'::jsonb)
            from jsonb_array_elements(v) e);
  elsif cls = 'cspace' then
    return jsonb_build_object(cname, v->cname);
  elsif cls = 'cfile' then
    return v;
  end if;
  return null;
end $$;

create or replace function public.kv_set(p_key text, p_value jsonb, p_admin text default null, p_cidx int default null, p_ccode text default null)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
declare cls text := public._key_class(p_key); cname text;
begin
  if cls in ('never','count') then return false; end if;
  if public._is_admin(p_admin) then
    insert into public.kv(key, value, updated_at) values (p_key, p_value, now())
      on conflict (key) do update set value = excluded.value, updated_at = now();
    return true;
  end if;
  cname := public._commission_name(p_cidx, p_ccode);
  if cname is null then return false; end if;
  if cls = 'cspace' then
    insert into public.kv(key, value, updated_at) values (p_key, jsonb_build_object(cname, p_value->cname), now())
      on conflict (key) do update
        set value = coalesce(public.kv.value, '{}'::jsonb) || jsonb_build_object(cname, p_value->cname), updated_at = now();
    return true;
  elsif cls = 'cfile' then
    insert into public.kv(key, value, updated_at) values (p_key, p_value, now())
      on conflict (key) do update set value = excluded.value, updated_at = now();
    return true;
  end if;
  return false;
end $$;

create or replace function public.kv_delete(p_key text, p_admin text default null, p_cidx int default null, p_ccode text default null)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
declare cls text := public._key_class(p_key);
begin
  if cls in ('never','count') then return false; end if;
  if public._is_admin(p_admin) or (cls = 'cfile' and public._commission_name(p_cidx, p_ccode) is not null) then
    delete from public.kv where key = p_key;
    return true;
  end if;
  return false;
end $$;

-- register_member change de signature (mot de passe + jeton de session en retour)
drop function if exists public.register_member(jsonb, jsonb);
create or replace function public.register_member(p_member jsonb, p_photo jsonb default null, p_password text default null)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare n int; mx int; mat text; m jsonb; cur jsonb; v_uid uuid; tok text; v_email text;
begin
  if coalesce(trim(p_member->>'nom'),'') = '' or coalesce(trim(p_member->>'prenom'),'') = ''
     or coalesce(trim(p_member->>'tel'),'') = '' then
    raise exception 'champs obligatoires manquants';
  end if;
  if p_photo is not null and length(p_photo::text) > 3500000 then
    raise exception 'photo trop volumineuse';
  end if;
  v_email := lower(trim(coalesce(p_member->>'email','')));
  perform public._check_new_account(v_email, p_password);
  perform pg_advisory_xact_lock(7001);
  select coalesce(value, '[]'::jsonb) into cur from public.kv where key = 'members';
  if cur is null then cur := '[]'::jsonb; end if;
  cur := public._members_frozen(cur);
  n := jsonb_array_length(cur);
  select coalesce(max(nullif(regexp_replace(coalesce(e->>'matricule',''), '\D', '', 'g'), '')::int), 0)
    into mx from jsonb_array_elements(cur) e;
  mat := 'KKHA-' || lpad((greatest(n, mx) + 1)::text, 4, '0');
  insert into public.member_accounts(email, pass_hash) values (v_email, crypt(p_password, gen_salt('bf')))
    returning uid into v_uid;
  m := jsonb_build_object(
    'matricule', mat,
    'uid', v_uid,
    'nom', left(p_member->>'nom', 120),
    'prenom', left(p_member->>'prenom', 120),
    'email', left(v_email, 200),
    'tel', left(p_member->>'tel', 40),
    'adresse', left(coalesce(p_member->>'adresse',''), 250),
    'dateInscription', to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'adhesionPayee', false,
    'hasPhoto', p_photo is not null
  );
  insert into public.kv(key, value) values ('members', cur || jsonb_build_array(m))
    on conflict (key) do update set value = excluded.value, updated_at = now();
  if p_photo is not null then
    insert into public.kv(key, value) values ('memberPhoto_' || mat, p_photo)
      on conflict (key) do update set value = excluded.value, updated_at = now();
  end if;
  tok := public._new_session(v_uid);
  return jsonb_build_object('matricule', mat, 'token', tok);
end $$;

-- connexion d'un membre : renvoie un jeton de session, ou null
create or replace function public.member_login(p_email text, p_password text) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare a record;
begin
  select * into a from public.member_accounts where lower(email) = lower(trim(coalesce(p_email,'')));
  if found and p_password is not null and a.pass_hash = crypt(p_password, a.pass_hash)
     and exists (select 1 from public.kv k, jsonb_array_elements(k.value) e where k.key = 'members' and e->>'uid' = a.uid::text) then
    return public._new_session(a.uid);
  end if;
  perform pg_sleep(0.6);
  return null;
end $$;

-- activation du compte d'un membre déjà inscrit avant l'introduction des comptes (matricule + téléphone)
create or replace function public.member_claim(p_matricule text, p_tel text, p_email text, p_password text) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare cur jsonb; idx int; v_uid uuid; v_email text := lower(trim(coalesce(p_email,''))); tel text := right(regexp_replace(coalesce(p_tel,''), '\D', '', 'g'), 9);
begin
  perform public._check_new_account(v_email, p_password);
  perform pg_advisory_xact_lock(7001);
  select coalesce(value, '[]'::jsonb) into cur from public.kv where key = 'members';
  cur := public._members_frozen(cur);
  select t.i::int into idx from jsonb_array_elements(cur) with ordinality as t(e, i)
   where upper(t.e->>'matricule') = upper(trim(coalesce(p_matricule,'')))
     and coalesce(t.e->>'uid','') = ''
     and length(tel) >= 8
     and right(regexp_replace(coalesce(t.e->>'tel',''), '\D', '', 'g'), 9) = tel;
  if idx is null then perform pg_sleep(0.6); raise exception 'CLAIM_FAILED'; end if;
  insert into public.member_accounts(email, pass_hash) values (v_email, crypt(p_password, gen_salt('bf')))
    returning uid into v_uid;
  update public.kv set updated_at = now(), value = (
    select jsonb_agg(case when t.i = idx then t.e || jsonb_build_object('uid', v_uid, 'email', v_email) else t.e end order by t.i)
    from jsonb_array_elements(cur) with ordinality as t(e, i)
  ) where key = 'members';
  return public._new_session(v_uid);
end $$;

create or replace function public.member_me(p_token text) returns jsonb
language sql stable security definer set search_path = public, extensions as $$
  select jsonb_build_object('uid', e->'uid', 'prenom', e->'prenom', 'nom', e->'nom', 'matricule', e->'matricule')
  from public.kv k, jsonb_array_elements(k.value) e
  where k.key = 'members' and public._member_uid(p_token) is not null
    and e->>'uid' = public._member_uid(p_token)::text
  limit 1;
$$;

create or replace function public.member_logout(p_token text) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
begin
  delete from public.member_sessions where p_token is not null and token_hash = encode(digest(p_token, 'sha256'), 'hex');
  return true;
end $$;

create or replace function public.member_change_password(p_token text, p_old text, p_new text) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
declare v_uid uuid := public._member_uid(p_token);
begin
  if v_uid is null or p_new is null or length(p_new) < 6 then return false; end if;
  if not exists (select 1 from public.member_accounts where uid = v_uid and pass_hash = crypt(p_old, pass_hash)) then
    perform pg_sleep(0.6); return false;
  end if;
  update public.member_accounts set pass_hash = crypt(p_new, gen_salt('bf')) where uid = v_uid;
  return true;
end $$;

-- administrateur : nouveau mot de passe temporaire pour un membre (renvoyé en clair, une seule fois)
create or replace function public.admin_reset_member_password(p_admin text, p_matricule text) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare v_uid uuid; tmp text;
begin
  if not public._is_admin(p_admin) then perform pg_sleep(0.6); return null; end if;
  select (e->>'uid')::uuid into v_uid from public.kv k, jsonb_array_elements(public._members_frozen(k.value)) e
   where k.key = 'members' and e->>'matricule' = p_matricule and coalesce(e->>'uid','') <> '';
  if v_uid is null then return null; end if;
  tmp := encode(gen_random_bytes(5), 'hex');
  update public.member_accounts set pass_hash = crypt(tmp, gen_salt('bf')) where uid = v_uid;
  delete from public.member_sessions where uid = v_uid;
  return tmp;
end $$;

-- administrateur : suppression DÉFINITIVE d'un membre (fiche, photo, compte, sessions)
-- puis renumérotation des matricules restants : KKHA-0001, KKHA-0002… sans trou.
create or replace function public.admin_delete_member(p_admin text, p_matricule text) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
declare cur jsonb; target jsonb; r record; newmat text;
begin
  if not public._is_admin(p_admin) then perform pg_sleep(0.6); return false; end if;
  perform pg_advisory_xact_lock(7001);
  select value into cur from public.kv where key = 'members';
  cur := public._members_frozen(cur);
  select e into target from jsonb_array_elements(cur) e where e->>'matricule' = p_matricule;
  if target is null then return false; end if;
  if coalesce(target->>'uid','') <> '' then
    delete from public.member_accounts where uid = (target->>'uid')::uuid;  -- supprime aussi ses sessions
  end if;
  delete from public.kv where key = 'memberPhoto_' || p_matricule;
  -- les photos sont déplacées dans l'ordre croissant : chaque nouvelle clé est toujours libre
  for r in
    select e->>'matricule' as old_mat, row_number() over (order by t.i) as pos
    from jsonb_array_elements(cur) with ordinality as t(e, i)
    where e->>'matricule' <> p_matricule
  loop
    newmat := 'KKHA-' || lpad(r.pos::text, 4, '0');
    if newmat <> r.old_mat then
      delete from public.kv where key = 'memberPhoto_' || newmat;
      update public.kv set key = 'memberPhoto_' || newmat, updated_at = now() where key = 'memberPhoto_' || r.old_mat;
    end if;
  end loop;
  update public.kv set updated_at = now(), value = coalesce((
    select jsonb_agg(t.e || jsonb_build_object('matricule', 'KKHA-' || lpad(t.pos::text, 4, '0')) order by t.pos)
    from (select e, row_number() over (order by i) as pos
          from jsonb_array_elements(cur) with ordinality as x(e, i)
          where e->>'matricule' <> p_matricule) t
  ), '[]'::jsonb) where key = 'members';
  return true;
end $$;

create or replace function public.admin_login(p_pass text) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
begin
  if public._is_admin(p_pass) then return true; end if;
  perform pg_sleep(0.6);
  return false;
end $$;

create or replace function public.admin_change_password(p_old text, p_new text) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public._is_admin(p_old) then perform pg_sleep(0.6); return false; end if;
  if p_new is null or length(p_new) < 6 then return false; end if;
  update public.app_secrets set value = crypt(p_new, gen_salt('bf')) where name = 'admin_hash';
  return true;
end $$;

-- ---------- droits ----------
revoke all on function public._is_admin(text) from public, anon, authenticated;
revoke all on function public._commission_name(int, text) from public, anon, authenticated;
revoke all on function public._key_class(text) from public, anon, authenticated;
revoke all on function public._member_uid(text) from public, anon, authenticated;
revoke all on function public._new_session(uuid) from public, anon, authenticated;
revoke all on function public._members_frozen(jsonb) from public, anon, authenticated;
revoke all on function public._check_new_account(text, text) from public, anon, authenticated;
revoke all on function public.kv_get(text, text, int, text, text) from public;
revoke all on function public.kv_set(text, jsonb, text, int, text) from public;
revoke all on function public.kv_delete(text, text, int, text) from public;
revoke all on function public.register_member(jsonb, jsonb, text) from public;
revoke all on function public.member_login(text, text) from public;
revoke all on function public.member_claim(text, text, text, text) from public;
revoke all on function public.member_me(text) from public;
revoke all on function public.member_logout(text) from public;
revoke all on function public.member_change_password(text, text, text) from public;
revoke all on function public.admin_reset_member_password(text, text) from public;
revoke all on function public.admin_delete_member(text, text) from public;
revoke all on function public.admin_login(text) from public;
revoke all on function public.admin_change_password(text, text) from public;
grant execute on function public.kv_get(text, text, int, text, text) to anon, authenticated;
grant execute on function public.kv_set(text, jsonb, text, int, text) to anon, authenticated;
grant execute on function public.kv_delete(text, text, int, text) to anon, authenticated;
grant execute on function public.register_member(jsonb, jsonb, text) to anon, authenticated;
grant execute on function public.member_login(text, text) to anon, authenticated;
grant execute on function public.member_claim(text, text, text, text) to anon, authenticated;
grant execute on function public.member_me(text) to anon, authenticated;
grant execute on function public.member_logout(text) to anon, authenticated;
grant execute on function public.member_change_password(text, text, text) to anon, authenticated;
grant execute on function public.admin_reset_member_password(text, text) to anon, authenticated;
grant execute on function public.admin_delete_member(text, text) to anon, authenticated;
grant execute on function public.admin_login(text) to anon, authenticated;
grant execute on function public.admin_change_password(text, text) to anon, authenticated;
