from __future__ import annotations
import json, os
import pandas as pd
from sqlalchemy import create_engine, text

try:
    import streamlit as st
    DB_URL = st.secrets["db"]["url"]
except Exception:
    DB_URL = os.getenv("DB_URL")

if not DB_URL:
    raise RuntimeError("Database URL not configured. Set st.secrets['db']['url'] or env DB_URL.")

_engine = create_engine(DB_URL, pool_pre_ping=True)

def df_read(sql: str, params: dict | None = None) -> pd.DataFrame:
    with _engine.begin() as cx:
        return pd.read_sql(text(sql), cx, params=params or {})

def df_write_replace(table: str, df: pd.DataFrame, index: bool = False):
    with _engine.begin() as cx:
        df.to_sql(table, cx, if_exists="replace", index=index)

def upsert_requirements(rows: list[dict]) -> None:
    if not rows: return
    cols = rows[0].keys()
    keys = ",".join(cols)
    placeholders = ",".join([f":{c}" for c in cols])
    sql = text(f"""        insert into requirements_log ({keys})
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
        cx.execute(text("""            insert into enabled_tabs (id, tabs) values (1, :s)
            on conflict (id) do update set tabs = :s
        """), {"s": s})

def read_company_meta() -> dict:
    df = df_read("select * from company_meta where id=1")
    if df.empty: return {}
    r = df.iloc[0].to_dict()
    return {"name": r.get("name"), "address_lines": [r.get("address_1",""), r.get("address_2","")]}

def write_company_meta(name: str, a1: str, a2: str):
    with _engine.begin() as cx:
        cx.execute(text("""            insert into company_meta (id, name, address_1, address_2)
            values (1, :n, :a1, :a2)
            on conflict (id) do update set name=:n, address_1=:a1, address_2=:a2
        """), {"n": name, "a1": a1, "a2": a2})
