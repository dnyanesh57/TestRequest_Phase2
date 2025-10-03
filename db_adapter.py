# db_adapter.py
from __future__ import annotations
import os
import json
from typing import Sequence
from urllib.parse import urlparse
from contextlib import contextmanager
import datetime as dt
import pandas as pd
from sqlalchemy import create_engine, text, inspect

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

# --- Add these imports at the top of db_adapter.py ---

@contextmanager
def _conn():
    with _engine.begin() as c:
        yield c

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
    with _conn() as c:
        rows = c.execute(text("SELECT vendor_key AS vendor, email FROM vendor_contacts ORDER BY vendor_key")).mappings().all()
        return pd.DataFrame(rows) if rows else pd.DataFrame(columns=["vendor", "email"])

def upsert_vendor_contact(vendor: str, email: str, by_email: str | None = None) -> None:
    """UPSERT a vendor's email (DB-only)."""
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
    with _conn() as c:
        r = c.execute(text("SELECT email FROM vendor_contacts WHERE vendor_key = :v"), {"v": vendor}).scalar()
        return r if r else None

def ensure_password_reset_tables() -> None:
    """Create password_reset_tokens table if missing."""
    with _conn() as c:
        if DB_URL.startswith("sqlite"):
            c.execute(text("""
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT NOT NULL,
                  token TEXT NOT NULL UNIQUE,
                  code_hash TEXT NOT NULL,
                  created_at TEXT NOT NULL DEFAULT (datetime('now')),
                  expires_at TEXT NOT NULL,
                  used_at TEXT,
                  requested_by TEXT
                )
            """))
            c.execute(text("CREATE INDEX IF NOT EXISTS idx_password_reset_email ON password_reset_tokens(email)"))
        else:
            c.execute(text("""
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                  id BIGSERIAL PRIMARY KEY,
                  email TEXT NOT NULL,
                  token TEXT NOT NULL UNIQUE,
                  code_hash TEXT NOT NULL,
                  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                  expires_at TIMESTAMPTZ NOT NULL,
                  used_at TIMESTAMPTZ,
                  requested_by TEXT
                )
            """))
            c.execute(text("CREATE INDEX IF NOT EXISTS idx_password_reset_email ON password_reset_tokens(email)"))


def create_password_reset_entry(email: str, token: str, code_hash: str, expires_at_iso: str, requested_by: str | None = None) -> None:
    """Insert a new password reset token, clearing previous unused tokens."""
    email = (email or '').strip().lower()
    if not email:
        raise ValueError('email required')
    with _conn() as c:
        if DB_URL.startswith('sqlite'):
            c.execute(text("DELETE FROM password_reset_tokens WHERE email = :em AND used_at IS NULL"), {"em": email})
            c.execute(text("""
                INSERT INTO password_reset_tokens(email, token, code_hash, expires_at, requested_by)
                VALUES (:em, :tk, :ch, :ex, :rb)
            """), {"em": email, "tk": token, "ch": code_hash, "ex": expires_at_iso, "rb": requested_by})
        else:
            c.execute(text("DELETE FROM password_reset_tokens WHERE email = :em AND used_at IS NULL"), {"em": email})
            ex_value = expires_at_iso
            if isinstance(expires_at_iso, str):
                try:
                    ex_value = dt.datetime.fromisoformat(expires_at_iso)
                except ValueError:
                    try:
                        ex_value = pd.to_datetime(expires_at_iso).to_pydatetime()
                    except Exception:
                        ex_value = dt.datetime.utcnow()
            c.execute(text("""
                INSERT INTO password_reset_tokens(email, token, code_hash, expires_at, requested_by)
                VALUES (:em, :tk, :ch, :ex, :rb)
            """), {"em": email, "tk": token, "ch": code_hash, "ex": ex_value, "rb": requested_by})


def fetch_password_reset(email: str, token: str) -> dict | None:
    email = (email or '').strip().lower()
    token = (token or '').strip()
    if not email or not token:
        return None
    with _conn() as c:
        row = c.execute(text("""
            SELECT email, token, code_hash, created_at, expires_at, used_at, requested_by
              FROM password_reset_tokens
             WHERE email = :em AND token = :tk
             ORDER BY created_at DESC
             LIMIT 1
        """), {"em": email, "tk": token}).mappings().first()
        return dict(row) if row else None


def mark_password_reset_used(token: str) -> None:
    token = (token or '').strip()
    if not token:
        return
    with _conn() as c:
        if DB_URL.startswith('sqlite'):
            c.execute(text("""
                UPDATE password_reset_tokens
                   SET used_at = datetime('now')
                 WHERE token = :tk
            """), {"tk": token})
        else:
            c.execute(text("""
                UPDATE password_reset_tokens
                   SET used_at = NOW()
                 WHERE token = :tk
            """), {"tk": token})


def update_user_password_hash(email: str, password_hash: str) -> None:
    email = (email or '').strip().lower()
    if not email:
        raise ValueError('email required')
    with _conn() as c:
        c.execute(text("UPDATE acl_users SET password_hash = :ph WHERE lower(email) = :em"), {"ph": password_hash, "em": email})
def log_requirement_email(ref: str, vendor: str, email: str, subject: str, ok: bool, error: str | None = None) -> None:
    """Audit log for outgoing requirement emails."""
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

def update_requirement_status(refs: list[str], status: str, approver_email: str,
                              status_detail: str | None = None, approved_at_iso: str | None = None):
    """
    Update requirement status fields for a list of refs.
    Allowed statuses: 'Approved', 'Rejected', 'Pending Admin Approval', 'Auto Approved'
    """
    if not refs: return
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
        # For SQLite fallback, ANY(..) is unsupported — use simple IN
        if DB_URL.startswith("sqlite"):
            q = text("""
                UPDATE requirements_log
                   SET status = :st,
                       approver = :appr,
                       approved_at = CASE WHEN :st = 'Approved' THEN :dt ELSE '' END,
                       status_detail = COALESCE(:det, status_detail)
                 WHERE ref IN (%s)
            """ % ",".join("?"*len(refs)))
            c.execute(q, [status, approver_email, approved_at_iso, status_detail] + refs)
        else:
            c.execute(q, {"st": status, "appr": approver_email, "dt": approved_at_iso, "det": status_detail, "refs": refs})

def read_requirements_by_refs(refs: list[str]) -> list[dict]:
    if not refs: return []
    with _conn() as c:
        if DB_URL.startswith("sqlite"):
            q = text("SELECT * FROM requirements_log WHERE ref IN (%s)" % ",".join("?"*len(refs)))
            rows = c.execute(q, refs).mappings().all()
        else:
            q = text("SELECT * FROM requirements_log WHERE ref = ANY(:refs)")
            rows = c.execute(q, {"refs": refs}).mappings().all()
        return [dict(r) for r in rows]

def update_requirement_qty(ref: str, new_qty: float, modified_by: str, comment: str) -> None:
    """Update the qty for a single requirement ref and append an audit note into status_detail.
    The audit note is prefixed with [QTY_MOD] and includes old->new, who and when, and the supplied comment.
    """
    if not ref:
        return
    ts = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    with _conn() as c:
        # fetch existing
        qsel = text("SELECT qty, status_detail FROM requirements_log WHERE ref = :r")
        row = c.execute(qsel, {"r": ref}).mappings().first()
        if not row:
            return
        old_qty = row["qty"]
        det = row.get("status_detail") or ""
        audit = f"[QTY_MOD {ts} by {modified_by}] {old_qty} -> {new_qty}. Reason: {comment.strip()}"
        new_det = (det + ("\n" if det else "") + audit)[:2000]
        qup = text("""
            UPDATE requirements_log
               SET qty = :q,
                   status_detail = :d
             WHERE ref = :r
        """)
        c.execute(qup, {"q": float(new_qty), "d": new_det, "r": ref})
    # structured audit log
    try:
        log_requirement_audit(ref, "qty_update", str(old_qty), str(new_qty), comment, modified_by)
    except Exception:
        pass
# -------------------- Existing API (unchanged logic) --------------------

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


# --- Site groups (persisted) ---
def ensure_site_groups_table() -> None:
    with _conn() as c:
        if DB_URL.startswith("sqlite"):
            c.execute(text("""
                CREATE TABLE IF NOT EXISTS site_groups (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  group_name TEXT UNIQUE NOT NULL,
                  sites TEXT NOT NULL,
                  emails TEXT NOT NULL DEFAULT '',
                  created_at TEXT NOT NULL DEFAULT (datetime('now')),
                  created_by TEXT,
                  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                  updated_by TEXT
                )
            """))
            try:
                # Add emails column if it doesn't exist (for migrations)
                c.execute(text("ALTER TABLE site_groups ADD COLUMN emails TEXT NOT NULL DEFAULT ''"))
            except Exception:
                pass
        else:
            c.execute(text("""
                CREATE TABLE IF NOT EXISTS site_groups (
                  id BIGSERIAL PRIMARY KEY,
                  group_name TEXT UNIQUE NOT NULL,
                  sites TEXT NOT NULL,
                  emails TEXT NOT NULL DEFAULT '',
                  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                  created_by TEXT,
                  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                  updated_by TEXT
                )
            """))
            c.execute(text("ALTER TABLE site_groups ADD COLUMN IF NOT EXISTS emails TEXT NOT NULL DEFAULT ''"))

def read_site_groups() -> pd.DataFrame:
    ensure_site_groups_table()
    df = df_read("select id, group_name, sites, emails, created_at, created_by, updated_at, updated_by from site_groups order by lower(group_name)")
    if df.empty:
        return pd.DataFrame(columns=["id", "group_name", "sites", "emails", "created_at", "created_by", "updated_at", "updated_by"])
    return df

def upsert_site_group(group_name: str, sites: Sequence[str] | None, emails: Sequence[str] | None, by_email: str | None = None) -> None:
    name = (group_name or "").strip()
    if not name:
        raise ValueError("group_name required")
    sites = sites or []
    site_tokens: list[str] = []
    for s in sites:
        token = str(s or "").strip()
        if token:
            site_tokens.append(token)
    if not site_tokens:
        raise ValueError("At least one site is required")
    sites_dedup = list(dict.fromkeys(site_tokens))
    sites_str = "|".join(sites_dedup)

    emails = emails or []
    email_tokens: list[str] = []
    for e in emails:
        token = str(e or "").strip()
        if token:
            email_tokens.append(token)
    emails_dedup = list(dict.fromkeys(email_tokens))
    emails_str = "|".join(emails_dedup)

    with _conn() as c:
        if DB_URL.startswith("sqlite"):
            c.execute(text("""
                INSERT INTO site_groups (group_name, sites, emails, created_by, updated_by)
                VALUES (:name, :sites, :emails, :by, :by)
                ON CONFLICT(group_name) DO UPDATE SET
                  sites = excluded.sites,
                  emails = excluded.emails,
                  updated_at = datetime('now'),
                  updated_by = excluded.updated_by
            """), {"name": name, "sites": sites_str, "emails": emails_str, "by": by_email})
        else:
            c.execute(text("""
                INSERT INTO site_groups (group_name, sites, emails, created_by, updated_by)
                VALUES (:name, :sites, :emails, :by, :by)
                ON CONFLICT (group_name) DO UPDATE SET
                  sites = excluded.sites,
                  emails = excluded.emails,
                  updated_at = NOW(),
                  updated_by = excluded.updated_by
            """), {"name": name, "sites": sites_str, "emails": emails_str, "by": by_email})

def delete_site_group(group_name: str) -> None:
    name = (group_name or "").strip()
    if not name:
        raise ValueError("group_name required")
    with _conn() as c:
        c.execute(text("DELETE FROM site_groups WHERE lower(group_name) = lower(:name)"), {"name": name})

# --- Requirement audit log (structured history) ---
def ensure_requirement_audit_table() -> None:
    """Create requirement_audit_log table if it doesn't exist."""
    with _conn() as c:
        if DB_URL.startswith("sqlite"):
            c.execute(text("""
                CREATE TABLE IF NOT EXISTS requirement_audit_log (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  ref TEXT NOT NULL,
                  action TEXT NOT NULL,
                  old_value TEXT,
                  new_value TEXT,
                  comment TEXT,
                  actor TEXT,
                  created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
            """))
            c.execute(text("CREATE INDEX IF NOT EXISTS idx_req_audit_ref ON requirement_audit_log(ref)"))
        else:
            c.execute(text("""
                CREATE TABLE IF NOT EXISTS requirement_audit_log (
                  id BIGSERIAL PRIMARY KEY,
                  ref TEXT NOT NULL,
                  action TEXT NOT NULL,
                  old_value TEXT,
                  new_value TEXT,
                  comment TEXT,
                  actor TEXT,
                  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """))
            c.execute(text("CREATE INDEX IF NOT EXISTS idx_req_audit_ref ON requirement_audit_log(ref)"))

def log_requirement_audit(ref: str, action: str, old_value: str | None, new_value: str | None, comment: str | None, actor: str | None) -> None:
    """Insert an audit row for a requirement reference."""
    if not ref or not action:
        return
    ensure_requirement_audit_table()
    with _conn() as c:
        c.execute(text("""
            INSERT INTO requirement_audit_log(ref, action, old_value, new_value, comment, actor)
            VALUES (:r, :a, :ov, :nv, :cm, :ac)
        """), {"r": ref, "a": action, "ov": old_value, "nv": new_value, "cm": (comment or ""), "ac": (actor or "")})

def _clean_row_for_db(row: dict) -> dict:
    clean = {}
    for k, v in row.items():
        if isinstance(v, pd.Timestamp):
            clean[k] = None if pd.isna(v) else v.to_pydatetime()
        elif isinstance(v, dt.datetime):
            clean[k] = v.tzinfo and v or v.replace(tzinfo=None)
        elif isinstance(v, float) and pd.isna(v):
            clean[k] = None
        elif isinstance(v, pd.Series) or isinstance(v, pd.DataFrame):
            clean[k] = None
        else:
            try:
                clean[k] = None if pd.isna(v) else v
            except Exception:
                clean[k] = v
    return clean


def upsert_requirements(rows: list[dict]) -> None:
    _ensure_requirements_log_table() # Ensure table exists before upserting
    if not rows: return
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
            cx.execute(sql, _clean_row_for_db(r))
def _table_exists(table_name: str) -> bool:
    """
    Checks if a table exists in the database.
    """
    with _engine.connect() as connection:
        inspector = inspect(connection)
        return table_name in inspector.get_table_names()

def _ensure_requirements_log_table():
    """
    Ensures the requirements_log table exists with a UNIQUE constraint on 'ref'.
    """
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
                  lot_number TEXT,
                  make TEXT,
                  material_quantity TEXT,
                  manufacturer TEXT,
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
            # Ensure unique index for 'ref' in SQLite if not already created inline
            c.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS idx_requirements_log_ref ON requirements_log(ref)"))
        else:
            c.execute(text("""
                CREATE TABLE IF NOT EXISTS requirements_log (
                  id BIGSERIAL PRIMARY KEY,
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
                  lot_number TEXT,
                  make TEXT,
                  material_quantity TEXT,
                  manufacturer TEXT,
                  remaining_at_request REAL,
                  approval_required BOOLEAN,
                  approval_reason TEXT,
                  is_new_item BOOLEAN,
                  generated_at TIMESTAMPTZ,
                  generated_by_name TEXT,
                  generated_by_email TEXT,
                  status TEXT,
                  approver TEXT,
                  approved_at TIMESTAMPTZ,
                  idem_key TEXT,
                  status_detail TEXT,
                  auto_approved_at TIMESTAMPTZ,
                  auto_approved_by TEXT,
                  engine_version TEXT,
                  snap_company_name TEXT,
                  snap_address_1 TEXT,
                  snap_address_2 TEXT
                )
            """))


        extras = [
            ('lot_number', 'TEXT'),
            ('make', 'TEXT'),
            ('material_quantity', 'TEXT'),
            ('manufacturer', 'TEXT')
        ]
        if DB_URL.startswith('sqlite'):
            for col, ddl in extras:
                try:
                    c.execute(text(f"ALTER TABLE requirements_log ADD COLUMN {col} {ddl}"))
                except Exception:
                    pass
        else:
            for col, ddl in extras:
                c.execute(text(f"ALTER TABLE requirements_log ADD COLUMN IF NOT EXISTS {col} {ddl}"))

def read_acl_df() -> pd.DataFrame:
    return df_read("select * from acl_users")

def write_acl_df(df: pd.DataFrame):
    with _engine.begin() as cx:
        cx.execute(text("delete from acl_users"))
    df_write_replace("acl_users", df, index=False)

def ensure_approval_recipient_tables() -> None:
    """Create approval_recipients table if it doesn't exist."""
    with _conn() as c: # type: ignore
        if DB_URL.startswith("sqlite"):
            c.execute(text("""
                CREATE TABLE IF NOT EXISTS approval_recipients (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  project_code TEXT NOT NULL,
                  vendor_key TEXT NOT NULL,
                  request_type TEXT NOT NULL,
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
                  project_code TEXT NOT NULL,
                  vendor_key TEXT NOT NULL,
                  request_type TEXT NOT NULL,
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
    with _conn() as c:
        rows = c.execute(text("SELECT * FROM approval_recipients ORDER BY project_code, vendor_key, request_type, email")).mappings().all()
        return pd.DataFrame(rows) if rows else pd.DataFrame(columns=["id", "project_code", "vendor_key", "request_type", "email", "created_at", "created_by"])
        
def upsert_approval_recipient(project_code: str|None, vendor_key: str|None, \
                              request_type: str|None, email: str, \
                              by_email: str|None=None, rec_id: int|None=None) -> None:
    """
    Insert/update an approval recipient. If rec_id is provided -> update; else insert new.
    """
    with _conn() as c: # type: ignore
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
                """), {"pc":project_code, "vk":vendor_key, "rt":request_type, "em":email, "by":by_email})
            else:
                c.execute(text("""
                    INSERT INTO approval_recipients(project_code, vendor_key, request_type, email, created_by, updated_by)
                    VALUES (:pc, :vk, :rt, :em, :by, :by)
                """), {"pc":project_code, "vk":vendor_key, "rt":request_type, "em":email, "by":by_email})

def delete_approval_recipient(rec_id: int) -> None:
    """Delete an approval recipient by ID."""
    with _conn() as c: # type: ignore
        c.execute(text("DELETE FROM approval_recipients WHERE id=:id"), {"id": rec_id})

def list_approver_emails(project_code: str|None, vendor_key: str|None, request_type: str|None) -> list[str]:
    """List emails of approvers for a given project, vendor, and request type."""
    with _conn() as c: # type: ignore
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

# --- Ensure emailed_* columns exist on requirements_log ---
def ensure_reqlog_email_columns() -> None:
    """
    Adds emailed_vendor_at, emailed_vendor_by columns to requirements_log if missing.
    Works for Postgres and SQLite.
    """
    with _conn() as c:
        if DB_URL.startswith("sqlite"):
            # Try creating columns; SQLite doesn't support IF NOT EXISTS for columns—wrap in try/except.
            try:
                c.execute(text("ALTER TABLE requirements_log ADD COLUMN emailed_vendor_at TEXT"))
            except Exception:
                pass
            try:
                c.execute(text("ALTER TABLE requirements_log ADD COLUMN emailed_vendor_by TEXT"))
            except Exception:
                pass
        else:
            c.execute(text("""
                ALTER TABLE requirements_log
                ADD COLUMN IF NOT EXISTS emailed_vendor_at TIMESTAMPTZ
            """))
            c.execute(text("""
                ALTER TABLE requirements_log
                ADD COLUMN IF NOT EXISTS emailed_vendor_by TEXT
            """))

def mark_vendor_emailed(refs: list[str], by_email: str) -> None:
    """
    Set emailed_vendor_at (now) and emailed_vendor_by for the given refs.
    """
    if not refs:
        return

    ensure_reqlog_email_columns()

    with _conn() as c:
        if DB_URL.startswith("sqlite"):
            # Build a dynamic IN (?, ?, ?)
            placeholders = ",".join("?" * len(refs))
            q = text(f"""
                UPDATE requirements_log
                   SET emailed_vendor_at = datetime('now'),
                       emailed_vendor_by = ?
                 WHERE ref IN ({placeholders})
            """)
            c.execute(q, [by_email] + refs)
        else:
            q = text("""
                UPDATE requirements_log
                   SET emailed_vendor_at = NOW(),
                       emailed_vendor_by = :by
                 WHERE ref = ANY(:refs)
            """)
            c.execute(q, {"by": by_email, "refs": refs})

def read_reqlog_df() -> pd.DataFrame:
    _ensure_requirements_log_table() # Ensure table exists before reading
    return df_read("select * from requirements_log order by generated_at desc")

def write_reqlog_df(df: pd.DataFrame):
    df_write_replace("requirements_log", df, index=False)


def read_enabled_tabs() -> list[str]:
    df = df_read("select tabs from enabled_tabs where id=1")
    if df.empty: return []
    try:
        return json.loads(df.iloc[0]["tabs"])
    except Exception:
        return []

def write_enabled_tabs(tabs: list[str]):
    s = json.dumps(tabs)
    with _engine.begin() as cx:
        cx.execute(text("""
            insert into enabled_tabs (id, tabs) values (1, :s)
            on conflict (id) do update set tabs = :s
        """), {"s": s})

def read_company_meta() -> dict:
    df = df_read("select * from company_meta where id=1")
    if df.empty: return {}
    r = df.iloc[0].to_dict()
    return {"name": r.get("name"), "address_lines": [r.get("address_1",""), r.get("address_2","")]}

def write_company_meta(name: str, a1: str, a2: str):
    with _engine.begin() as cx:
        cx.execute(text("""
            insert into company_meta (id, name, address_1, address_2)
            values (1, :n, :a1, :a2)
            on conflict (id) do update set name=:n, address_1=:a1, address_2=:a2
        """), {"n": name, "a1": a1, "a2": a2})

# --- Subcontract Team Emails ---
def ensure_subcontract_team_table() -> None:
    """Create subcontract_team table if it doesn't exist."""
    with _conn() as c:
        if DB_URL.startswith("sqlite"):
            c.execute(text("""
                CREATE TABLE IF NOT EXISTS subcontract_team (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT UNIQUE NOT NULL,
                  created_at TEXT NOT NULL DEFAULT (datetime('now')),
                  created_by TEXT
                )
            """))
        else:
            c.execute(text("""
                CREATE TABLE IF NOT EXISTS subcontract_team (
                  id BIGSERIAL PRIMARY KEY,
                  email TEXT UNIQUE NOT NULL,
                  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                  created_by TEXT
                )
            """))

def read_subcontract_team_emails() -> list[str]:
    """Return a list of emails for the subcontract team."""
    ensure_subcontract_team_table()
    with _conn() as c:
        rows = c.execute(text("SELECT email FROM subcontract_team ORDER BY lower(email)")).scalars().all()
        return rows or []

def add_subcontract_team_email(email: str, by_email: str | None = None) -> None:
    """Add an email to the subcontract team, ignoring duplicates."""
    email = (email or "").strip().lower()
    if not email:
        raise ValueError("Email is required")
    ensure_subcontract_team_table()
    with _conn() as c:
        if DB_URL.startswith("sqlite"):
            c.execute(text("""
                INSERT INTO subcontract_team (email, created_by)
                VALUES (:email, :by)
                ON CONFLICT(email) DO NOTHING
            """), {"email": email, "by": by_email})
        else:
            c.execute(text("""
                INSERT INTO subcontract_team (email, created_by)
                VALUES (:email, :by)
                ON CONFLICT (email) DO NOTHING
            """), {"email": email, "by": by_email})

def delete_subcontract_team_email(email: str) -> None:
    """Remove an email from the subcontract team."""
    email = (email or "").strip().lower()
    if not email:
        return
    ensure_subcontract_team_table()
    with _conn() as c:
        c.execute(text("DELETE FROM subcontract_team WHERE lower(email) = :email"), {"email": email})
