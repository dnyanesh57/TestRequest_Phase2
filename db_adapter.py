# db_adapter.py
from __future__ import annotations
import os
import json
from urllib.parse import urlparse
from contextlib import contextmanager
import datetime as dt
import pandas as pd
from sqlalchemy import create_engine, text, inspect
from typing import Optional, List, Dict, Tuple
import hashlib, secrets

# ---- Read URL (from Streamlit secrets first, else env) ----
try:
    import streamlit as st  # type: ignore
    DB_URL = st.secrets["db"]["url"]
    SUPABASE_IPV4 = st.secrets["db"].get("ipv4", os.getenv("SUPABASE_IPV4", ""))  # optional
except Exception: # Fallback for local development without Streamlit secrets
    DB_URL = os.getenv("DATABASE_URL") or os.getenv("DB_URL") or "sqlite:///sjcpl.db"
    SUPABASE_IPV4 = os.getenv("SUPABASE_IPV4", "")
    
if not DB_URL:
    raise RuntimeError("Database URL not configured. Set st.secrets['db']['url'] or env DB_URL.")

# Ensure the psycopg2 dialect so libpq connect args work
if DB_URL.startswith("postgresql://"):
    DB_URL = "postgresql+psycopg2://" + DB_URL[len("postgresql://") :]

# Extract hostname for SNI/cert verification (keeps TLS happy even when forcing IPv4)
parsed = urlparse(DB_URL.replace("+psycopg2", ""))  # scheme part not needed for parsing netloc
host_for_sni = parsed.hostname or ""

# Build connect args (safe in any Postgres; IPv4 optional)
connect_args = {
    "sslmode": "require",
    # Keep the TLS server name consistent with the certificate
    **({"host": host_for_sni} if host_for_sni else {}),
    # If you set SUPABASE_IPV4 / secrets['db']['ipv4'], libpq will dial IPv4 directly
    **({"hostaddr": SUPABASE_IPV4} if SUPABASE_IPV4 else {}),
    # Production-grade network hygiene
    "connect_timeout": 5,
    "keepalives": 1,
    "keepalives_idle": 30,
    "keepalives_interval": 10,
    "keepalives_count": 5,
    "application_name": "sjcpl-phase2-app",
}

# Single global engine (do not create engines elsewhere)
_engine = create_engine(DB_URL, connect_args=connect_args, pool_pre_ping=True, future=True)

@contextmanager
def _conn():
    with _engine.begin() as c:
        yield c

# --- NaT/NULL sanitizers ---
def _none_if_nat(v):
    """Return None for pandas.NaT/NaN/empty-string; otherwise pass the value through."""
    try:
        import pandas as pd
        import numpy as np
        if v is None:
            return None
        # Treat pandas NaT/NaN
        try:
            if pd.isna(v):
                return None # Return None for pandas NaT/NaN
        except Exception:
            pass
        # Treat string "NaT" or blanks as NULL
        if isinstance(v, str) and v.strip().upper() in ("NAT", ""):
            return None
        return v
    except Exception:
        # Fallback: only treat literal string 'NaT' and blanks as null
        if v is None:
            return None
        if isinstance(v, str) and v.strip().upper() in ("NAT", ""):
            return None
        return v

# Normalize a row dict before insert/update
_TS_FIELDS = {
    "generated_at","approved_at","auto_approved_at",
    "emailed_vendor_at","vendor_emailed_at",
    "emailed_requester_at","requester_emailed_at",
}
def _sanitize_row_timestamps(row: dict) -> dict:
    for k in list(row.keys()):
        if k in _TS_FIELDS:
            row[k] = _none_if_nat(row.get(k))
    return row

# -------------------- Utilities --------------------
def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _table_exists(table_name: str) -> bool:
    with _engine.connect() as connection:
        inspector = inspect(connection)
        return table_name in inspector.get_table_names()

# -------------------- Core tables ensure (NEW) --------------------
def _ensure_acl_users_table():
    with _conn() as c:
        if DB_URL.startswith("sqlite"):
            c.execute(text("""
                CREATE TABLE IF NOT EXISTS acl_users (
                  email TEXT PRIMARY KEY,
                  name TEXT NOT NULL DEFAULT '',
                  role TEXT NOT NULL DEFAULT 'user',
                  sites TEXT NOT NULL DEFAULT '',
                  tabs TEXT NOT NULL DEFAULT '',
                  can_raise INTEGER NOT NULL DEFAULT 1,
                  can_view_registry INTEGER NOT NULL DEFAULT 1,
                  can_export INTEGER NOT NULL DEFAULT 1,
                  can_email_drafts INTEGER NOT NULL DEFAULT 1,
                  password_hash TEXT NOT NULL DEFAULT ''
                )
            """))
        else:
            c.execute(text("""
                CREATE TABLE IF NOT EXISTS acl_users (
                  email TEXT PRIMARY KEY,
                  name TEXT NOT NULL DEFAULT '',
                  role TEXT NOT NULL DEFAULT 'user',
                  sites TEXT NOT NULL DEFAULT '',
                  tabs TEXT NOT NULL DEFAULT '',
                  can_raise BOOLEAN NOT NULL DEFAULT TRUE,
                  can_view_registry BOOLEAN NOT NULL DEFAULT TRUE,
                  can_export BOOLEAN NOT NULL DEFAULT TRUE,
                  can_email_drafts BOOLEAN NOT NULL DEFAULT TRUE,
                  password_hash TEXT NOT NULL DEFAULT ''
                )
            """))

def _ensure_enabled_tabs_table():
    with _conn() as c:
        if DB_URL.startswith("sqlite"):
            c.execute(text("""
                CREATE TABLE IF NOT EXISTS enabled_tabs (
                  id INTEGER PRIMARY KEY,
                  tabs TEXT NOT NULL
                )
            """))
        else:
            c.execute(text("""
                CREATE TABLE IF NOT EXISTS enabled_tabs (
                  id INTEGER PRIMARY KEY,
                  tabs TEXT NOT NULL
                )
            """))
        # seed a row if empty
        c.execute(text("""
            INSERT INTO enabled_tabs (id, tabs)
            SELECT 1, '[]'
            WHERE NOT EXISTS (SELECT 1 FROM enabled_tabs WHERE id=1)
        """))

def _ensure_company_meta_table():
    with _conn() as c:
        if DB_URL.startswith("sqlite"):
            c.execute(text("""
                CREATE TABLE IF NOT EXISTS company_meta (
                  id INTEGER PRIMARY KEY,
                  name TEXT NOT NULL DEFAULT '',
                  address_1 TEXT NOT NULL DEFAULT '',
                  address_2 TEXT NOT NULL DEFAULT ''
                )
            """))
        else:
            c.execute(text("""
                CREATE TABLE IF NOT EXISTS company_meta (
                  id INTEGER PRIMARY KEY,
                  name TEXT NOT NULL DEFAULT '',
                  address_1 TEXT NOT NULL DEFAULT '',
                  address_2 TEXT NOT NULL DEFAULT ''
                )
            """))
        # seed a row if empty
        c.execute(text("""
            INSERT INTO company_meta (id, name, address_1, address_2)
            SELECT 1, 'SJ Contracts Pvt Ltd',
                      'SJ Contracts Pvt Ltd, 305 - 308 Amar Business Park',
                      'Baner Road, Opp. Sadanand Hotel, Baner, Pune – 411045'
            WHERE NOT EXISTS (SELECT 1 FROM company_meta WHERE id=1)
        """))

# -------------------- Requirements log ensure (existing + email flags) --------------------
def _ensure_requirements_log_table():
    with _conn() as c:
        if DB_URL.startswith("sqlite"):
            c.execute(text("""
                CREATE TABLE IF NOT EXISTS requirements_log (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  ref TEXT NOT NULL UNIQUE,
                  hash TEXT,
                  project_code TEXT,
                  project_name TEXT,
                  request_type TEXT,
                  vendor TEXT,
                  wo TEXT,
                  line_key TEXT,
                  uom TEXT,
                  stage TEXT,
                  description TEXT,
                  qty REAL,
                  date_casting TEXT,
                  date_testing TEXT,
                  remarks TEXT,
                  remaining_at_request REAL,
                  approval_required BOOLEAN,
                  approval_reason TEXT,
                  is_new_item BOOLEAN,
                  generated_at TEXT,
                  generated_by_name TEXT,
                  generated_by_email TEXT,
                  status TEXT,
                  approver TEXT,
                  approved_at TEXT,
                  idem_key TEXT,
                  status_detail TEXT,
                  auto_approved_at TEXT,
                  auto_approved_by TEXT,
                  engine_version TEXT,
                  snap_company_name TEXT,
                  snap_address_1 TEXT,
                  snap_address_2 TEXT
                )
            """))
            c.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS idx_requirements_log_ref ON requirements_log(ref)"))
        else:
            c.execute(text("""
                CREATE TABLE IF NOT EXISTS requirements_log (
                  id BIGSERIAL PRIMARY KEY,
                  ref TEXT NOT NULL UNIQUE,
                  hash TEXT, project_code TEXT, project_name TEXT, request_type TEXT, vendor TEXT, wo TEXT,
                  line_key TEXT, uom TEXT, stage TEXT, description TEXT, qty REAL,
                  date_casting TEXT, date_testing TEXT, remarks TEXT, remaining_at_request REAL,
                  approval_required BOOLEAN, approval_reason TEXT, is_new_item BOOLEAN,
                  generated_at TIMESTAMPTZ, generated_by_name TEXT, generated_by_email TEXT,
                  status TEXT, approver TEXT, approved_at TIMESTAMPTZ,
                  idem_key TEXT, status_detail TEXT, auto_approved_at TIMESTAMPTZ, auto_approved_by TEXT,
                  engine_version TEXT, snap_company_name TEXT, snap_address_1 TEXT, snap_address_2 TEXT
                )
            """))
    # also ensure email-flag columns
    ensure_reqlog_email_columns()

# --- Ensure emailed_* columns exist on requirements_log (UPDATED to support both names) ---
def ensure_reqlog_email_columns() -> None:
    """
    Adds BOTH legacy (vendor_emailed_*) and current (emailed_vendor_*) columns,
    and also requester equivalents. Safe/idempotent.
    """
    with _conn() as c:
        if DB_URL.startswith("sqlite"):
            for col in [
                "emailed_vendor_at TEXT", "emailed_vendor_by TEXT",
                "vendor_emailed_at TEXT", "vendor_emailed_by TEXT",
                "emailed_requester_at TEXT", "emailed_requester_by TEXT",
                "requester_emailed_at TEXT", "requester_emailed_by TEXT",
            ]:
                try:
                    c.execute(text(f"ALTER TABLE requirements_log ADD COLUMN {col}"))
                except Exception:
                    pass
        else:
            for col, dtype in [
                ("emailed_vendor_at", "TIMESTAMPTZ"),
                ("emailed_vendor_by", "TEXT"),
                ("vendor_emailed_at", "TIMESTAMPTZ"),
                ("vendor_emailed_by", "TEXT"),
                ("emailed_requester_at", "TIMESTAMPTZ"),
                ("emailed_requester_by", "TEXT"),
                ("requester_emailed_at", "TIMESTAMPTZ"),
                ("requester_emailed_by", "TEXT"),
            ]:
                c.execute(text(f"ALTER TABLE requirements_log ADD COLUMN IF NOT EXISTS {col} {dtype}"))

# -------------------- Vendor email directory & logs (yours) --------------------
def ensure_vendor_email_tables() -> None:
    """Create vendor_contacts + requirement_mail_log if they don't exist."""
    with _conn() as c:
        if DB_URL.startswith("sqlite"):
            c.execute(text("""
                CREATE TABLE IF NOT EXISTS vendor_contacts (
                  vendor_key TEXT PRIMARY KEY,
                  email TEXT NOT NULL,
                  created_at TEXT NOT NULL DEFAULT (datetime('now')),
                  created_by TEXT,
                  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                  updated_by TEXT
                )
            """))
            c.execute(text("""
                CREATE TABLE IF NOT EXISTS requirement_mail_log (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  ref TEXT NOT NULL,
                  vendor_key TEXT,
                  email TEXT,
                  subject TEXT,
                  ok INTEGER NOT NULL,
                  error TEXT,
                  sent_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
            """))
            c.execute(text("CREATE INDEX IF NOT EXISTS idx_requirement_mail_log_ref ON requirement_mail_log(ref)"))
        else:
            c.execute(text("""
                CREATE TABLE IF NOT EXISTS vendor_contacts (
                  vendor_key TEXT PRIMARY KEY,
                  email TEXT NOT NULL,
                  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                  created_by TEXT,
                  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                  updated_by TEXT
                )
            """))
            c.execute(text("""
                CREATE TABLE IF NOT EXISTS requirement_mail_log (
                  id BIGSERIAL PRIMARY KEY,
                  ref TEXT NOT NULL,
                  vendor_key TEXT,
                  email TEXT,
                  subject TEXT,
                  ok BOOLEAN NOT NULL,
                  error TEXT,
                  sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """))
            c.execute(text("CREATE INDEX IF NOT EXISTS idx_requirement_mail_log_ref ON requirement_mail_log(ref)"))

def read_vendor_contacts() -> pd.DataFrame:
    """Return DataFrame with columns ['vendor','email'] (vendor is Subcontractor_Key)."""
    ensure_vendor_email_tables()
    with _conn() as c:
        rows = c.execute(text("SELECT vendor_key AS vendor, email FROM vendor_contacts ORDER BY vendor_key")).mappings().all()
        return pd.DataFrame(rows) if rows else pd.DataFrame(columns=["vendor", "email"])

def upsert_vendor_contact(vendor: str, email: str, by_email: str | None = None) -> None:
    """UPSERT a vendor's email (DB-only)."""
    ensure_vendor_email_tables()
    vendor = (vendor or "").strip()
    email = (email or "").strip()
    if not vendor or not email:
        raise ValueError("vendor and email are required")
    with _conn() as c:
        if DB_URL.startswith("sqlite"):
            c.execute(text("""
                INSERT INTO vendor_contacts(vendor_key, email, created_by, updated_by)
                VALUES (:v, :e, :by, :by)
                ON CONFLICT(vendor_key) DO UPDATE SET
                  email = excluded.email,
                  updated_at = datetime('now'),
                  updated_by = excluded.updated_by
            """), {"v": vendor, "e": email, "by": by_email})
        else:
            c.execute(text("""
                INSERT INTO vendor_contacts(vendor_key, email, created_by, updated_by)
                VALUES (:v, :e, :by, :by)
                ON CONFLICT (vendor_key) DO UPDATE SET
                  email = EXCLUDED.email,
                  updated_at = NOW(),
                  updated_by = EXCLUDED.updated_by
            """), {"v": vendor, "e": email, "by": by_email})

def get_vendor_email(vendor: str) -> str | None:
    """Convenience lookup for a single vendor email."""
    ensure_vendor_email_tables()
    with _conn() as c:
        r = c.execute(text("SELECT email FROM vendor_contacts WHERE vendor_key = :v"), {"v": vendor}).scalar()
        return r if r else None

def log_requirement_email(ref: str, vendor: str, email: str, subject: str, ok: bool, error: str | None = None) -> None:
    """Audit log for outgoing requirement emails."""
    ensure_vendor_email_tables()
    with _conn() as c:
        if DB_URL.startswith("sqlite"):
            c.execute(text("""
                INSERT INTO requirement_mail_log(ref, vendor_key, email, subject, ok, error)
                VALUES (:ref, :vendor, :email, :subject, :ok, :error)
            """), {"ref": ref, "vendor": vendor, "email": email, "subject": subject, "ok": 1 if ok else 0, "error": error})
        else:
            c.execute(text("""
                INSERT INTO requirement_mail_log(ref, vendor_key, email, subject, ok, error)
                VALUES (:ref, :vendor, :email, :subject, :ok, :error)
            """), {"ref": ref, "vendor": vendor, "email": email, "subject": subject, "ok": ok, "error": error})

# -------------------- Requirements ops (existing) --------------------
def df_read(sql: str, params: dict | None = None) -> pd.DataFrame: # type: ignore
    _ensure_requirements_log_table() # Ensure table exists before reading
    with _engine.begin() as cx:
        return pd.read_sql(text(sql), cx, params=params or {})

def df_write_replace(table: str, df: pd.DataFrame, index: bool = False):
    with _engine.begin() as cx:
        df.to_sql(table, cx, if_exists="replace", index=index)

# --- App settings (persisted) ---
def _ensure_app_settings_table():
    with _engine.begin() as cx:
        cx.execute(text("""
            create table if not exists app_settings (
              id int primary key,
              use_github boolean not null default true,
              github_repo text default 'dnyanesh57/NC_Dashboard',
              github_branch text default 'main',
              github_folder text default 'data'
            )
        """))
        # seed a row if empty
        cx.execute(text("""
            insert into app_settings (id) values (1)
            on conflict (id) do nothing
        """))

def read_app_settings() -> dict:
    _ensure_app_settings_table()
    df = df_read("select * from app_settings where id=1")
    if df.empty:
        return {
            "use_github": True,
            "github_repo": "dnyanesh57/NC_Dashboard",
            "github_branch": "main",
            "github_folder": "data",
        }
    r = df.iloc[0].to_dict()
    return {
        "use_github": bool(r.get("use_github", True)),
        "github_repo": r.get("github_repo") or "dnyanesh57/NC_Dashboard",
        "github_branch": r.get("github_branch") or "main",
        "github_folder": r.get("github_folder") or "data",
    }

def write_app_settings(use_github: bool, repo: str, branch: str, folder: str) -> None:
    _ensure_app_settings_table()
    with _engine.begin() as cx:
        cx.execute(text("""
            insert into app_settings (id, use_github, github_repo, github_branch, github_folder)
            values (1, :use_github, :repo, :branch, :folder)
            on conflict (id) do update set
              use_github = excluded.use_github,
              github_repo = excluded.github_repo,
              github_branch = excluded.github_branch,
              github_folder = excluded.github_folder
        """), dict(use_github=bool(use_github), repo=repo, branch=branch, folder=folder))

# --- Upsert requirements (kept) ---
def upsert_requirements(rows: list[dict]) -> None:
    _ensure_requirements_log_table() # Ensure table exists before upserting
    if not rows: return
    # sanitize first (prevents 'NaT' into timestamptz)
    rows = [_sanitize_row_timestamps(dict(r)) for r in rows]
    # Convert any remaining pd.NaT to None for database insertion
    for row in rows:
        for k, v in row.items():
            row[k] = None if pd.isna(v) else v
    cols = rows[0].keys()
    keys = ",".join(cols)
    placeholders = ",".join([f":{c}" for c in cols])
    sql = text(f"""
        insert into requirements_log ({keys})
        values ({placeholders})
        on conflict (ref) do update set
          hash=excluded.hash,
          status=excluded.status,
          approver=excluded.approver,
          approved_at=excluded.approved_at,
          status_detail=excluded.status_detail,
          auto_approved_at=excluded.auto_approved_at,
          auto_approved_by=excluded.auto_approved_by
    """)
    with _engine.begin() as cx:
        for r in rows:
            cx.execute(sql, r)

# -------------------- ACL (ensure + read/write) --------------------
def read_acl_df() -> pd.DataFrame:
    _ensure_acl_users_table()
    return df_read("select * from acl_users")

def write_acl_df(df: pd.DataFrame):
    _ensure_acl_users_table()
    with _engine.begin() as cx:
        cx.execute(text("delete from acl_users"))
    df_write_replace("acl_users", df, index=False)

# -------------------- Approval recipients (your schema) --------------------
def ensure_approval_recipient_tables() -> None:
    """Create approval_recipients table if it doesn't exist."""
    with _conn() as c:
        if DB_URL.startswith("sqlite"):
            c.execute(text("""
                CREATE TABLE IF NOT EXISTS approval_recipients (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  project_code TEXT,
                  vendor_key TEXT,
                  request_type TEXT,
                  email TEXT NOT NULL,
                  created_at TEXT NOT NULL DEFAULT (datetime('now')), 
                  updated_at TEXT NOT NULL DEFAULT (datetime('now')), 
                  updated_by TEXT,
                  created_by TEXT,
                  UNIQUE (project_code, vendor_key, request_type, email)
                )
            """))
        else:
            c.execute(text("""
                CREATE TABLE IF NOT EXISTS approval_recipients (
                  id BIGSERIAL PRIMARY KEY,
                  project_code TEXT,
                  vendor_key TEXT,
                  request_type TEXT,
                  email TEXT NOT NULL,
                  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), 
                  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), 
                  updated_by TEXT,
                  created_by TEXT,
                  UNIQUE (project_code, vendor_key, request_type, email)
                )
            """))

def read_approval_recipients() -> pd.DataFrame:
    """Return DataFrame with approval recipients."""
    ensure_approval_recipient_tables()
    with _conn() as c:
        rows = c.execute(text("SELECT * FROM approval_recipients ORDER BY project_code NULLS FIRST, vendor_key NULLS FIRST, request_type NULLS FIRST, email")).mappings().all()
        return pd.DataFrame(rows) if rows else pd.DataFrame(columns=["id", "project_code", "vendor_key", "request_type", "email", "created_at", "created_by"])

def upsert_approval_recipient(project_code: str|None, vendor_key: str|None, \
                              request_type: str|None, email: str, \
                              by_email: str|None=None, rec_id: int|None=None) -> None:
    """
    Insert/update an approval recipient. If rec_id is provided -> update; else insert new.
    """
    ensure_approval_recipient_tables()
    with _conn() as c:
        if rec_id:
            if DB_URL.startswith("sqlite"):
                c.execute(text("""
                    UPDATE approval_recipients
                       SET project_code=:pc, vendor_key=:vk, request_type=:rt, email=:em,
                           updated_at=datetime('now'), updated_by=:by 
                     WHERE id=:id
                """), {"pc":project_code, "vk":vendor_key, "rt":request_type, "em":email, "by":by_email, "id":rec_id})
            else:
                c.execute(text("""
                    UPDATE approval_recipients
                       SET project_code=:pc, vendor_key=:vk, request_type=:rt, email=:em,
                           updated_at=NOW(), updated_by=:by 
                     WHERE id=:id
                """), {"pc":project_code, "vk":vendor_key, "rt":request_type, "em":email, "by":by_email, "id":rec_id})
        else:
            if DB_URL.startswith("sqlite"):
                c.execute(text("""
                    INSERT INTO approval_recipients(project_code, vendor_key, request_type, email, created_by, updated_by)
                    VALUES (:pc, :vk, :rt, :em, :by, :by)
                    ON CONFLICT(project_code, vendor_key, request_type, email) DO NOTHING
                """), {"pc":project_code, "vk":vendor_key, "rt":request_type, "em":email, "by":by_email})
            else:
                c.execute(text("""
                    INSERT INTO approval_recipients(project_code, vendor_key, request_type, email, created_by, updated_by)
                    VALUES (:pc, :vk, :rt, :em, :by, :by)
                    ON CONFLICT (project_code, vendor_key, request_type, email) DO NOTHING
                """), {"pc":project_code, "vk":vendor_key, "rt":request_type, "em":email, "by":by_email})

def delete_approval_recipient(rec_id: int) -> None:
    """Delete an approval recipient by ID."""
    ensure_approval_recipient_tables()
    with _conn() as c:
        c.execute(text("DELETE FROM approval_recipients WHERE id=:id"), {"id": rec_id})

def list_approver_emails(project_code: str|None, vendor_key: str|None, request_type: str|None) -> list[str]:
    """List emails of approvers for a given project, vendor, and request type."""
    ensure_approval_recipient_tables()
    with _conn() as c:
        q = text("""
            SELECT DISTINCT email, 3 as prio FROM approval_recipients 
              WHERE (project_code = :pc) AND (vendor_key = :vk) AND (request_type = :rt)
            UNION
            SELECT DISTINCT email, 2 FROM approval_recipients 
              WHERE (project_code = :pc) AND (vendor_key = :vk) AND (request_type IS NULL)
            UNION
            SELECT DISTINCT email, 2 FROM approval_recipients 
              WHERE (project_code = :pc) AND (vendor_key IS NULL) AND (request_type = :rt)
            UNION
            SELECT DISTINCT email, 2 FROM approval_recipients 
              WHERE (project_code IS NULL) AND (vendor_key = :vk) AND (request_type = :rt)
            UNION
            SELECT DISTINCT email, 1 FROM approval_recipients 
              WHERE (project_code = :pc) AND (vendor_key IS NULL) AND (request_type IS NULL)
            UNION
            SELECT DISTINCT email, 1 FROM approval_recipients 
              WHERE (project_code IS NULL) AND (vendor_key = :vk) AND (request_type IS NULL)
            UNION
            SELECT DISTINCT email, 1 FROM approval_recipients 
              WHERE (project_code IS NULL) AND (vendor_key IS NULL) AND (request_type = :rt)
            UNION
            SELECT DISTINCT email, 0 FROM approval_recipients 
              WHERE (project_code IS NULL) AND (vendor_key IS NULL) AND (request_type IS NULL)
        """)
        rows = c.execute(q, {"pc": project_code, "vk": vendor_key, "rt": request_type}).mappings().all()
        seen, out = set(), []
        for r in sorted(rows, key=lambda x: x["prio"], reverse=True):
            em = r["email"]
            if em and em not in seen:
                seen.add(em); out.append(em)
        return out

# -------------------- Requirement status ops (yours) --------------------
def update_requirement_status(refs: list[str], status: str, approver_email: str,
                              status_detail: str | None = None, approved_at_iso: str | None = None):
    """
    Update requirement status fields for a list of refs.
    Allowed statuses: 'Approved', 'Rejected', 'Pending Admin Approval', 'Auto Approved'
    """
    if not refs: return
    _ensure_requirements_log_table()
    if approved_at_iso is None:
        approved_at_iso = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    with _conn() as c:
        # Update only the fields we need; 'approved_at' on rejection can be blank if you prefer
        q = text("""
            UPDATE requirements_log
               SET status = :st,
                   approver = :appr,
                   approved_at = CASE WHEN :st = 'Approved' THEN :dt ELSE '' END,
                   status_detail = COALESCE(:det, status_detail)
             WHERE ref = ANY(:refs)
        """)
        if DB_URL.startswith("sqlite"):
            q = text("""
                UPDATE requirements_log
                   SET status = ?,
                       approver = ?,
                       approved_at = CASE WHEN ? = 'Approved' THEN ? ELSE '' END,
                       status_detail = COALESCE(?, status_detail)
                 WHERE ref IN (%s)
            """ % ",".join("?"*len(refs)))
            c.execute(q, [status, approver_email, status, approved_at_iso, status_detail] + refs)
        else:
            c.execute(q, {"st": status, "appr": approver_email, "dt": approved_at_iso, "det": status_detail, "refs": refs})

def read_requirements_by_refs(refs: list[str]) -> list[dict]:
    if not refs: return []
    _ensure_requirements_log_table()
    with _conn() as c:
        if DB_URL.startswith("sqlite"):
            q = text("SELECT * FROM requirements_log WHERE ref IN (%s)" % ",".join("?"*len(refs)))
            rows = c.execute(q, refs).mappings().all()
        else:
            q = text("SELECT * FROM requirements_log WHERE ref = ANY(:refs)")
            rows = c.execute(q, {"refs": refs}).mappings().all()
        return [dict(r) for r in rows]

# -------------------- Email sent flags (NEW) --------------------
def mark_vendor_emailed(refs: list[str], by_email: str) -> None:
    """
    Set vendor emailed flags (compatible names).
    """
    if not refs:
        return
    _ensure_requirements_log_table()
    ensure_reqlog_email_columns()
    with _conn() as c:
        if DB_URL.startswith("sqlite"):
            placeholders = ",".join("?" * len(refs))
            q = text(f"""
                UPDATE requirements_log
                   SET emailed_vendor_at = datetime('now'),
                       emailed_vendor_by = ?,
                       vendor_emailed_at = datetime('now'),
                       vendor_emailed_by = ?
                 WHERE ref IN ({placeholders})
            """)
            c.execute(q, [by_email, by_email] + refs)
        else:
            q = text("""
                UPDATE requirements_log
                   SET emailed_vendor_at = NOW(),
                       emailed_vendor_by = :by,
                       vendor_emailed_at = NOW(),
                       vendor_emailed_by = :by
                 WHERE ref = ANY(:refs)
            """)
            c.execute(q, {"by": by_email, "refs": refs})

def mark_requester_emailed(refs: list[str], by_email: str) -> None:
    """
    Set requester emailed flags (compatible names).
    """
    if not refs:
        return
    _ensure_requirements_log_table()
    ensure_reqlog_email_columns()
    with _conn() as c:
        if DB_URL.startswith("sqlite"):
            placeholders = ",".join("?" * len(refs))
            q = text(f"""
                UPDATE requirements_log
                   SET emailed_requester_at = datetime('now'),
                       emailed_requester_by = ?,
                       requester_emailed_at = datetime('now'),
                       requester_emailed_by = ?
                 WHERE ref IN ({placeholders})
            """)
            c.execute(q, [by_email, by_email] + refs)
        else:
            q = text("""
                UPDATE requirements_log
                   SET emailed_requester_at = NOW(),
                       emailed_requester_by = :by,
                       requester_emailed_at = NOW(),
                       requester_emailed_by = :by
                 WHERE ref = ANY(:refs)
            """)
            c.execute(q, {"by": by_email, "refs": refs})

# -------------------- Reqlog / tabs / company meta (yours + ensure) --------------------
def read_reqlog_df() -> pd.DataFrame:
    _ensure_requirements_log_table()
    return df_read("select * from requirements_log order by generated_at desc")

def write_reqlog_df(df: pd.DataFrame):
    _ensure_requirements_log_table()
    df_write_replace("requirements_log", df, index=False)

def read_enabled_tabs() -> list[str]:
    _ensure_enabled_tabs_table()
    df = df_read("select tabs from enabled_tabs where id=1")
    if df.empty: return []
    try:
        return json.loads(df.iloc[0]["tabs"])
    except Exception:
        return []

def write_enabled_tabs(tabs: list[str]):
    _ensure_enabled_tabs_table()
    s = json.dumps(tabs)
    with _engine.begin() as cx:
        cx.execute(text("""
            insert into enabled_tabs (id, tabs) values (1, :s)
            on conflict (id) do update set tabs = :s
        """), {"s": s})

def read_company_meta() -> dict:
    _ensure_company_meta_table()
    df = df_read("select * from company_meta where id=1")
    if df.empty: return {}
    r = df.iloc[0].to_dict()
    return {"name": r.get("name"), "address_lines": [r.get("address_1",""), r.get("address_2","")]}

def write_company_meta(name: str, a1: str, a2: str):
    _ensure_company_meta_table()
    with _engine.begin() as cx:
        cx.execute(text("""
            insert into company_meta (id, name, address_1, address_2)
            values (1, :n, :a1, :a2)
            on conflict (id) do update set name=:n, address_1=:a1, address_2=:a2
        """), {"n": name, "a1": a1, "a2": a2})

# -------------------- Password: change & reset (NEW) --------------------
def _ensure_password_resets_table():
    with _conn() as c:
        if DB_URL.startswith("sqlite"):
            c.execute(text("""
                CREATE TABLE IF NOT EXISTS password_resets (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT NOT NULL,
                  token TEXT NOT NULL UNIQUE,
                  expires_at TEXT NOT NULL,
                  used_at TEXT,
                  created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
            """))
            c.execute(text("CREATE INDEX IF NOT EXISTS idx_password_resets_email ON password_resets(email)"))
        else:
            c.execute(text("""
                CREATE TABLE IF NOT EXISTS password_resets (
                  id BIGSERIAL PRIMARY KEY,
                  email TEXT NOT NULL,
                  token TEXT NOT NULL UNIQUE,
                  expires_at TIMESTAMPTZ NOT NULL,
                  used_at TIMESTAMPTZ,
                  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """))
            c.execute(text("CREATE INDEX IF NOT EXISTS idx_password_resets_email ON password_resets(email)"))

def change_password(email: str, old_password: str, new_password: str) -> Tuple[bool, str]:
    _ensure_acl_users_table()
    with _conn() as c:
        row = c.execute(text("SELECT password_hash FROM acl_users WHERE lower(email)=lower(:em)"),
                        {"em": email}).fetchone()
        if not row:
            return False, "User not found."
        if _sha256_hex(old_password) != (row[0] or ""):
            return False, "Current password is incorrect."
        ph = _sha256_hex(new_password)
        c.execute(text("UPDATE acl_users SET password_hash=:ph WHERE lower(email)=lower(:em)"),
                  {"ph": ph, "em": email})
    return True, "Password updated."

def set_user_password(email: str, new_password: str) -> bool:
    _ensure_acl_users_table()
    ph = _sha256_hex(new_password)
    with _conn() as c:
        res = c.execute(text("UPDATE acl_users SET password_hash=:ph WHERE lower(email)=lower(:em)"),
                        {"ph": ph, "em": email})
        return (res.rowcount or 0) > 0

def _utcnow() -> dt.datetime:
    # Use timezone-aware for Postgres, string for SQLite is okay
    return dt.datetime.utcnow()

def start_password_reset(email: str, ttl_minutes: int = 30) -> Tuple[bool, str, Optional[str], Optional[dt.datetime]]:
    _ensure_acl_users_table()
    _ensure_password_resets_table()
    token = secrets.token_urlsafe(24)
    expires = _utcnow() + dt.timedelta(minutes=ttl_minutes)
    with _conn() as c:
        user_row = c.execute(text("SELECT 1 FROM acl_users WHERE lower(email)=lower(:em)"), {"em": email}).fetchone()
        if not user_row:
            return False, "User not found.", None, None
        if DB_URL.startswith("sqlite"):
            c.execute(text("INSERT INTO password_resets (email, token, expires_at) VALUES (lower(:em), :tok, :exp)"),
                      {"em": email, "tok": token, "exp": expires.isoformat(timespec="seconds")})
        else:
            c.execute(text("INSERT INTO password_resets (email, token, expires_at) VALUES (lower(:em), :tok, :exp)"),
                      {"em": email, "tok": token, "exp": expires})
    return True, "Reset link generated.", token, expires

def verify_reset_token(token: str) -> Optional[str]:
    _ensure_password_resets_table()
    with _conn() as c:
        row = c.execute(text("SELECT email, expires_at, used_at FROM password_resets WHERE token=:tok"),
                        {"tok": token}).fetchone()
        if not row:
            return None
        email, exp, used = row
        # Normalize exp to datetime
        if isinstance(exp, str):
            try: exp_dt = dt.datetime.fromisoformat(exp)
            except Exception: return None
        else:
            exp_dt = exp
        if used is not None:
            return None
        if exp_dt is None or _utcnow() > exp_dt:
            return None
        return email

def complete_password_reset(token: str, new_password: str) -> Tuple[bool, str, Optional[str]]:
    email = verify_reset_token(token)
    if not email:
        return False, "Reset link is invalid or expired.", None
    _ensure_acl_users_table()
    _ensure_password_resets_table()
    ph = _sha256_hex(new_password)
    now = _utcnow()
    with _conn() as c:
        c.execute(text("UPDATE acl_users SET password_hash=:ph WHERE lower(email)=lower(:em)"),
                  {"ph": ph, "em": email})
        if DB_URL.startswith("sqlite"):
            c.execute(text("UPDATE password_resets SET used_at=:now WHERE token=:tok"),
                      {"now": now.isoformat(timespec='seconds'), "tok": token})
        else:
            c.execute(text("UPDATE password_resets SET used_at=:now WHERE token=:tok"),
                      {"now": now, "tok": token})
    return True, "Password has been reset.", email

def cleanup_expired_password_resets(retain_days: int = 30) -> int:
    _ensure_password_resets_table()
    cutoff = _utcnow() - dt.timedelta(days=retain_days)
    with _conn() as c:
        if DB_URL.startswith("sqlite"):
            res = c.execute(
                text("""
                  DELETE FROM password_resets
                  WHERE ( (strftime('%s', expires_at) < strftime('%s', 'now')) OR used_at IS NOT NULL )
                    AND (strftime('%s', created_at) < strftime('%s', :cut))
                """),
                {"cut": cutoff.isoformat(timespec="seconds")}
            )
        else:
            res = c.execute(
                text("""
                  DELETE FROM password_resets
                  WHERE (expires_at < NOW() OR used_at IS NOT NULL)
                    AND created_at < :cutoff
                """),
                {"cutoff": cutoff}
            )
        return res.rowcount or 0
