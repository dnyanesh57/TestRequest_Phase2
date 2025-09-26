-- Postgres schema for SJCPL WO dashboard persistence
create table if not exists acl_users (
  email text primary key,
  name text not null,
  role text not null default 'user',
  sites text not null default '*',
  tabs  text not null default '*',
  can_raise boolean not null default true,
  can_view_registry boolean not null default true,
  can_export boolean not null default true,
  can_email_drafts boolean not null default true,
  password_hash text not null
);

create table if not exists requirements_log (
  ref text primary key,
  hash text,
  project_code text,
  project_name text,
  request_type text,
  vendor text,
  wo text,
  line_key text,
  uom text,
  stage text,
  description text,
  qty double precision,
  date_casting text,
  date_testing text,
  remarks text,
  remaining_at_request text,
  approval_required boolean,
  approval_reason text,
  is_new_item boolean,
  generated_at text,
  generated_by_name text,
  generated_by_email text,
  status text,
  approver text,
  approved_at text,
  idem_key text unique,
  status_detail text,
  auto_approved_at text,
  auto_approved_by text,
  engine_version text,
  snap_company_name text,
  snap_address_1 text,
  snap_address_2 text
);

create table if not exists enabled_tabs (
  id int primary key default 1,
  tabs text not null
);

create table if not exists company_meta (
  id int primary key default 1,
  name text,
  address_1 text,
  address_2 text
);

insert into enabled_tabs (id, tabs)
values (1, '["Overview","Group: WO → Project","Work Order Explorer","Lifecycle","Subcontractor Summary","Browse","Status as on Date","Export","Email Drafts","Diagnostics","Raise Requirement","My Requests","Requirements Registry","Admin"]')
on conflict (id) do nothing;
