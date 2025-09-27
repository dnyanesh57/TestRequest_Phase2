# db_adapter.py
from __future__ import annotations
import json, os
from urllib.parse import urlparse
from contextlib import contextmanager
import pandas as pd
from sqlalchemy import create_engine, text

# ---- Read URL (from Streamlit secrets first, else env) ----
try:
    import streamlit as st  # type: ignore
    DB_URL = st.secrets["db"]["url"]
    SUPABASE_IPV4 = st.secrets["db"].get("ipv4", os.getenv("SUPABASE_IPV4", ""))  # optional
except Exception:
    DB_URL = os.getenv("DB_URL")
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
_engine = create_engine(DB_URL, connect_args=connect_args, pool_pre_ping=True)

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

# -------------------- Existing API (unchanged logic) --------------------

def df_read(sql: str, params: dict | None = None) -> pd.DataFrame:
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


def upsert_requirements(rows: list[dict]) -> None:
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
            cx.execute(sql, r)

def read_acl_df() -> pd.DataFrame:
    return df_read("select * from acl_users")

def write_acl_df(df: pd.DataFrame):
    with _engine.begin() as cx:
        cx.execute(text("delete from acl_users"))
    df_write_replace("acl_users", df, index=False)

def read_reqlog_df() -> pd.DataFrame:
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
