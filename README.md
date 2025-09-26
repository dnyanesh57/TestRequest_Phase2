# SJCPL — Work Order Dashboard (Phase 1 + 2) — Cloud Deploy (DB-backed)

This scaffold keeps your **existing logic unchanged** and adds **Postgres persistence**.

## Files

- `db_adapter.py` — tiny DB layer (SQLAlchemy + psycopg2)
- `schema.sql` — create tables in Neon/Supabase
- `requirements.txt` — runtime libs
- `.streamlit/secrets.example.toml` — template for local dev (do not commit your real secrets)
- **Your app file remains your source of truth**: `wo_phase2_dashboard_sjcpl.py` (not included here). Apply the *small* search/replace edits below.

---

## 1) Create a free Postgres
- Neon or Supabase → copy the connection URI (e.g., `postgresql://...`).
- Run `schema.sql` in their SQL console one time.

## 2) Configure secrets
On Streamlit Cloud → App → Settings → **Secrets**:
```toml
[db]
url = "postgresql+psycopg2://USER:PASSWORD@HOST:PORT/DBNAME"
REQ_HASH_SALT = "SJCPL-PHASE2-HASH-SALT"
```

## 3) Minimal edits to your `wo_phase2_dashboard_sjcpl.py` (no logic changes)

### a) Imports — add this line
```python
from db_adapter import (
    read_acl_df, write_acl_df,
    read_reqlog_df, write_reqlog_df,
    read_enabled_tabs, write_enabled_tabs,
    read_company_meta, write_company_meta,
    upsert_requirements
)
```

### b) Replace file-backed helpers with DB-backed ones

**Before (examples in your file):**
```python
ACL_FILE_NAME    = "acl_users.csv"
REQ_LOG_NAME     = "requirements_log.csv"
ENABLED_TABS_FILE = "enabled_tabs.json"
```

**After (simply remove/ignore these constants)** — no replacements needed once DB functions are used.

**Replace the loading/saving functions:**

- `_ensure_acl_in_state()`
```python
def _ensure_acl_in_state():
    if "acl_df" not in st.session_state:
        df = read_acl_df()
        if df.empty:
            import pandas as pd
            df = pd.DataFrame([{
                "email":"admin@sjcpl.local","name":"Admin","role":"master_admin",
                "sites":"*","tabs":"*","can_raise":True,"can_view_registry":True,
                "can_export":True,"can_email_drafts":True,
                "password_hash":_sha256_hex("admin")
            }])
            write_acl_df(df)
        st.session_state.acl_df = df
```

- `_ensure_reqlog_in_state()`
```python
def _ensure_reqlog_in_state():
    if "reqlog_df" not in st.session_state:
        st.session_state.reqlog_df = read_reqlog_df()
```

- Where you previously used `_save_csv_safe(st.session_state.reqlog_df, REQ_LOG_NAME)` → **replace** with:
```python
write_reqlog_df(st.session_state.reqlog_df)
```

- Enabled tabs
```python
def _load_enabled_tabs():
    t = read_enabled_tabs()
    return t if t else ["Overview","Group: WO → Project","Work Order Explorer","Lifecycle","Subcontractor Summary","Browse","Status as on Date","Export","Email Drafts","Diagnostics","Raise Requirement","My Requests","Requirements Registry","Admin"]

def _save_enabled_tabs(lst):
    write_enabled_tabs(lst)
```

- Company meta (optional)
  - On startup, instead of default only:
    ```python
    from db_adapter import read_company_meta, write_company_meta
    st.session_state.company_meta = read_company_meta() or COMPANY_DEFAULT.copy()
    ```
  - In Admin “Apply” click handler:
    ```python
    write_company_meta(name, addr1, addr2)
    ```

- During “Generate PDF & Log”, after you prepare `updated_df` (your logic untouched), **persist**:
```python
write_reqlog_df(updated_df)   # or upsert_requirements(pages_rows) for incremental
st.session_state.reqlog_df = read_reqlog_df()
```

That’s it — the rest of your business logic remains intact.

## 4) Deploy to Streamlit Community Cloud

1. Push repo with:
   - `wo_phase2_dashboard_sjcpl.py` (your app)
   - `db_adapter.py`
   - `requirements.txt`
   - `schema.sql`
2. Create the app on https://share.streamlit.io
3. Paste **secrets** (above)
4. Deploy

## 5) Optional: Hugging Face Spaces
- Create Space (SDK: Streamlit)
- Add same files
- Set **DB_URL** as a Space secret or keep Streamlit-style `st.secrets` by using a `secrets.toml` in Space settings.

---

### Tips
- Use `st.cache_data` for heavy computations (you already do ✅).
- Keep uploads in-memory; store only **registry/ACL/meta** in DB.
- For production hardening later: switch password hashing to `bcrypt/argon2` and add audit columns.
