# wo_phase2_dashboard_sjcpl.py
# SJCPL — Work Order Dashboard (Phase 1 + Phase 2) — Integrated Engine
# Final, Complete, and Functional Version (with password reset)
from __future__ import annotations
import io, os, uuid, hmac, hashlib, json, base64,requests
import datetime as dt
from typing import Dict, List, Sequence, Tuple, Optional
from db_adapter import (
    read_acl_df, write_acl_df,
    read_reqlog_df, write_reqlog_df,
    read_enabled_tabs, write_enabled_tabs,
    read_company_meta, write_company_meta,
    upsert_requirements,
    # Add these with your other db_adapter imports:
    read_vendor_contacts, upsert_vendor_contact, get_vendor_email, 
    log_requirement_email, ensure_vendor_email_tables,
    ensure_approval_recipient_tables, read_approval_recipients,
    mark_vendor_emailed, ensure_reqlog_email_columns, # Add these with your other db_adapter imports:
    upsert_approval_recipient, delete_approval_recipient, list_approver_emails,

    
    update_requirement_status, read_requirements_by_refs, _conn,
    
    read_app_settings, write_app_settings,   # NEW
    # Password reset helpers from your db layer (make sure they exist in db_adapter)
    start_password_reset, verify_reset_token, complete_password_reset,

)
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import urllib.request
import urllib.error
import pytz

import urllib.parse  # NEW for deep links
# PDF (pure-Python)
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm

# SMTP (for email drafts)
import smtplib, ssl
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image as RLImage

# ----------------------------- Brand / Theme -----------------------------
APP_TITLE = "SJCPL — Test Request and Approval V1"
BRAND_BLUE = "#00AEDA"; BRAND_BLACK = "#000000"; BRAND_GREY = "#939598"; BRAND_WHITE = "#FFFFFF"
PLOTLY_COLORS = [BRAND_BLUE, BRAND_BLACK, BRAND_GREY, "#146C94", "#4A4A4A"]

st.set_page_config(page_title=APP_TITLE, page_icon="📑", layout="wide")
pd.options.mode.copy_on_write = True
px.defaults.template = "plotly_white"; px.defaults.color_discrete_sequence = PLOTLY_COLORS

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap');
html, body, [class*="css"]  { font-family: 'Roboto', sans-serif; }
.big-title { font-size: 32px; font-weight: 800; margin: 0 0 0.2rem 0;
  background: linear-gradient(90deg, #00AEDA 0%, #000000 50%, #939598 100%);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.subtle { color: #4d4d4d; margin-top: -8px; }
hr.brand { border: none; height: 4px; background: linear-gradient(90deg,#00AEDA,#939598); border-radius: 2px; }
div.stButton>button, .stDownloadButton>button {
  border-radius: 10px; padding: 0.5rem 1rem; font-weight: 600; border: 1px solid #00AEDA33;
}
.lowpill { display:inline-block; padding:2px 8px; border-radius:999px; background:#ffe5e5; color:#c40000; font-weight:600; font-size:12px; }
.codebox { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  background:#f6f8fa; border:1px solid #e1e4e8; border-radius:8px; padding:10px; white-space:pre-wrap; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap');
html, body, [class*="css"]  { font-family: 'Roboto', sans-serif; }
.big-title { font-size: 32px; font-weight: 800; margin: 0 0 0.2rem 0;
  background: linear-gradient(90deg, #00AEDA 0%, #000000 50%, #939598 100%);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.subtle { color: #4d4d4d; margin-top: -8px; }
hr.brand { border: none; height: 4px; background: linear-gradient(90deg,#00AEDA,#939598); border-radius: 2px; }
div.stButton>button, .stDownloadButton>button {
  border-radius: 10px; padding: 0.5rem 1rem; font-weight: 600; border: 1px solid #00AEDA33;
}
.lowpill { display:inline-block; padding:2px 8px; border-radius:999px; background:#ffe5e5; color:#c40000; font-weight:600; font-size:12px; }
.codebox { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  background:#f6f8fa; border:1px solid #e1e4e8; border-radius:8px; padding:10px; white-space:pre-wrap; }
</style>
""", unsafe_allow_html=True)
# Token landing page
DEFAULT_GH_REPO   = "dnyanesh57/TestRequest_Phase2"  # <--- your repo

# ================== HARDENED PASSWORD RESET GATE (place VERY HIGH) ==================
import urllib.parse

# Try both query param APIs so it works across Streamlit versions
try:
    _QP = st.query_params  # modern
except Exception:
    _QP = st.experimental_get_query_params()  # legacy

def _qp_get(name: str, default: str = "") -> str:
    v = _QP.get(name, default)
    if isinstance(v, list):
        return v[0] if v else default
    return v or default

# Optional: set ?debug=1 to see incoming params on screen
_DEBUG = _qp_get("debug")
if _DEBUG:
    st.info(f"Debug params: {dict(_QP)}")

_view = _qp_get("view")
if _view == "reset":
    token = _qp_get("token")
    # Show something on screen no matter what, so it can never be “blank”
    st.markdown("## 🔐 Reset your password")
    if not token:
        st.error("Missing reset token in the URL.")
        st.stop()

    # import here so a missing function shows *on screen* instead of a blank page
    try:
        from db_adapter import verify_reset_token, complete_password_reset
    except Exception as e:
        st.error(f"Adapter import error: {e}")
        st.stop()

    # Pre-check the token and show any error visibly
    try:
        email_for_token = verify_reset_token(token)
    except Exception as e:
        email_for_token = None
        st.error(f"Token verification exception: {e}")
DEFAULT_GH_FOLDER = "data"                           # folder inside repo
DEFAULT_GH_BRANCH = "master" 

GITHUB_TOKEN = None
try:
    GITHUB_TOKEN = st.secrets.get("github", {}).get("token")
except Exception:
    pass
if not GITHUB_TOKEN:
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
def brand_header():
    st.markdown(f'<div class="big-title">{APP_TITLE}</div>', unsafe_allow_html=True)
    st.markdown('<div class="subtle">V1_0926</div>', unsafe_allow_html=True)
    st.markdown('<hr class="brand" />', unsafe_allow_html=True)


# ----- Deep-link & URL helpers -----
try:
    APP_BASE_URL = st.secrets.get("app", {}).get("base_url", "").rstrip("/")
except Exception:
    APP_BASE_URL = os.getenv("APP_BASE_URL", "").rstrip("/")

def app_link(**params) -> str:
    """
    Build a link to this app with query params (e.g., view='reset', token='...').
    If no APP_BASE_URL is configured, returns '?k=v' (works as in-app link).
    """
    qp = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    if APP_BASE_URL and qp:
        return f"{APP_BASE_URL}?{qp}"
    if APP_BASE_URL:
        return APP_BASE_URL
    return f"?{qp}" if qp else "?"


    if not email_for_token:
        st.error("This reset link is invalid or has expired.")
        st.stop()

    # Render the simple form (avoid any custom headers or login blocks here)
    p1 = st.text_input("New password", type="password")
    p2 = st.text_input("Confirm new password", type="password")
    colA, colB = st.columns([1,1])
    with colA:
        if st.button("Update password", type="primary"):
            if not p1 or not p2:
                st.error("Please enter and confirm your password.")
            elif p1 != p2:
                st.error("Passwords do not match.")
            else:
                try:
                    ok, msg, em = complete_password_reset(token, p1)
                    if ok:
                        st.success("Password updated. You can now sign in from the login panel.")
                    else:
                        st.error(msg or "Reset failed.")
                except Exception as e:
                    st.error(f"Error completing reset: {e}")
    with colB:
        # Relative link back to app root; works even if base URL isn’t set
        st.link_button("Back to app", "?", type="secondary")

    st.stop()
# =====================================================================
# Ensure vendor email & mail-log tables exist
# Ensure DB tables exist (single calls, don’t block UI if they fail)
try:
    ensure_vendor_email_tables()
    ensure_approval_recipient_tables()
    ensure_reqlog_email_columns()
    
except Exception as e:
    st.warning(f"DB init (email/approval tables) failed: {e}")

# SMTP + mail helpers (add once, top-level)
from email.mime.text import MIMEText
from email import encoders

def _smtp_config_ok() -> tuple[bool, dict]:
    """
    Read SMTP settings from st.secrets without mutating it.
    Required: host, port, user, password, from_email
    Optional: from_name (default), force_ssl (bool), timeout (int seconds)
    """
    raw = (st.secrets.get("smtp", {}) or {})
    port_val = raw.get("port", 587)
    try:
        port = int(str(port_val).strip())
    except Exception:
        port = 587
    cfg = {
        "host": raw.get("host"),
        "port": port,
        "user": raw.get("user"),
        "password": raw.get("password"),
        "from_email": raw.get("from_email"),
        "from_name": (raw.get("from_name") or "SJCPL Notifications"),
        "force_ssl": bool(raw.get("force_ssl", False)),
        "timeout": int(raw.get("timeout", 20)),
    }
    ok = all(cfg.get(k) for k in ["host","port","user","password","from_email"])
    return ok, cfg

def _build_mime_message(cfg: dict, to_email: str, subject: str, html_body: str,
                        attachment_bytes: bytes | None, attachment_name: str | None) -> MIMEMultipart:
    msg = MIMEMultipart()
    msg["From"] = f"{cfg['from_name']} <{cfg['from_email']}>"
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(html_body or "", "html"))
    if attachment_bytes:
        part = MIMEBase("application", "pdf")
        part.set_payload(attachment_bytes)
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f'attachment; filename="{attachment_name or "attachment.pdf"}"')
        msg.attach(part)
    return msg

def build_vendor_email_html(row: dict) -> str:
    proj = row.get("project_name") or row.get("project_code") or ""
    ref = row.get("ref","")
    req_type = row.get("request_type","")
    vendor = row.get("vendor","")
    desc = row.get("description","")
    uom = row.get("uom","")
    qty = f"{row.get('qty',''):.2f}" if isinstance(row.get('qty'), (int, float)) else str(row.get('qty',''))
    stage = row.get("stage","")
    dt_gen = row.get("generated_at","")
    line_item = row.get("line_item", "")
    return f"""
    <div style="font-family:Arial,Helvetica,sans-serif;color:#222">
      <p>Dear Vendor <b>{vendor}</b>,</p>
      <p>Please find attached the requirement reference <b>{ref}</b> for project <b>{proj}</b>.</p>
      <table style="border-collapse:collapse;font-size:13px;width:100%">
        <tr><td style="padding:4px 8px"><b>Type</b></td><td style="padding:4px 8px">{req_type}</td></tr>
        <tr><td style="padding:4px 8px"><b>Item</b></td><td style="padding:4px 8px">{desc}</td></tr>
      <tr><td style="padding:4px 8px"><b>Line Item</b></td><td style="padding:4px 8px">{line_item or '-'}</td></tr>
      <tr><td style="padding:4px 8px"><b>Item</b></td><td style="padding:4px 8px">{desc}</td></tr>
      <tr><td style="padding:4px 8px"><b>Qty</b></td><td style="padding:4px 8px">{qty} {uom}</td></tr>
        <tr><td style="padding:4px 8px"><b>Stage</b></td><td style="padding:4px 8px">{stage or '-'}</td></tr>
        <tr><td style="padding:4px 8px"><b>Generated</b></td><td style="padding:4px 8px">{dt_gen}</td></tr>
      </table>
      <p>Please review the attached PDF for full details.</p>
      <p>Regards,<br/>SJCPL — Test Request and Approval</p>
    </div>
    """

def build_vendor_email_subject(row: dict) -> str:
    """
    Subject used for vendor emails. Keep this identical to auto-approval.
    If you already had a subject builder, replace this with your exact logic.
    """
    proj = row.get("project_name") or row.get("project_code") or ""
    ref  = row.get("ref", "")
    req_type = row.get("request_type", "")
    # Example subject used widely; adjust if your auto-approval uses a different text:
    return f"[SJCPL] {req_type} — {proj} — {ref}"

def build_autoapproved_vendor_subject_and_body(row: dict, requester_name: str) -> Tuple[str, str]:
    """
    Builds the subject and HTML body for an auto-approved vendor email.
    This is a helper function to keep the email logic consistent.
    """
    proj = row.get("project_name") or row.get("project_code") or ""
    ref = row.get("ref","")
    req_type = row.get("request_type", "")
    return f"[SJCPL] {req_type} — {proj} — {ref}"
def send_email_via_smtp(to_email: str, subject: str, html_body: str,
                        attachment_bytes: bytes | None, attachment_name: str | None) -> tuple[bool, str]:
    """
    Robust sender:
      - STARTTLS on cfg.port (default 587)
      - Fallback to implicit SSL on 465 if connection is closed or fails
      - Proper EHLO -> STARTTLS -> EHLO sequence
      - Clear error messages for common Gmail misconfig
    """
    ok, cfg = _smtp_config_ok()
    if not ok:
        return False, "SMTP is not configured. Add [smtp] to .streamlit/secrets.toml (host, port, user, password, from_email)."

    # Gmail sanity check (common source of ‘connection closed’ during auth)
    if "gmail.com" in (cfg["host"] or "").lower():
        # App Password (not account password) is required if 2FA is on, and FROM must match USER.
        if cfg["from_email"].lower() != cfg["user"].lower():
            return False, "Gmail requires from_email == user. Set both to the same Gmail address."
    msg = _build_mime_message(cfg, to_email, subject, html_body, attachment_bytes, attachment_name)

    context = ssl.create_default_context()
    last_err = None

    def _try_starttls():
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=cfg["timeout"]) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(cfg["user"], cfg["password"])
            server.sendmail(cfg["from_email"], [to_email], msg.as_string())

    def _try_ssl_465():
        with smtplib.SMTP_SSL(cfg["host"], 465, timeout=cfg["timeout"], context=context) as server:
            server.ehlo()
            server.login(cfg["user"], cfg["password"])
            server.sendmail(cfg["from_email"], [to_email], msg.as_string())

    try:
        if cfg["force_ssl"]:
            _try_ssl_465()
            return True, "sent via SSL:465"
        # First try STARTTLS (587 or user-specified)
        _try_starttls()
        return True, f"sent via STARTTLS:{cfg['port']}"
    except (smtplib.SMTPServerDisconnected, smtplib.SMTPException, OSError) as e:
        last_err = e
        # Fallback to implicit SSL:465
        try:
            _try_ssl_465()
            return True, "sent via SSL:465 (fallback)"
        except Exception as e2:
            # Compose helpful message
            hint = []
            if "timed out" in str(last_err).lower() or "timed out" in str(e2).lower():
                hint.append("Network timeout—your host may block outbound SMTP. Try SSL:465 or an email API (SendGrid/Mailgun/SES).")
            if "gmail" in (cfg["host"] or "").lower():
                hint.append("For Gmail: use an App Password, and set from_email == user.")
            return False, f"{type(e2).__name__}: {e2}. Prior: {type(last_err).__name__}: {last_err}. " + (" ".join(hint) if hint else "")

if "app_settings" not in st.session_state:
    st.session_state.app_settings = {
        "data_source": "github",          # 'github' by default (local upload disabled unless admin changes)
        "github_repo": DEFAULT_GH_REPO,
        "github_folder": DEFAULT_GH_FOLDER,
        "github_branch": DEFAULT_GH_BRANCH,
    }
# Show logged-in user at the top-right of the app
u = st.session_state.get("user", {})
st.markdown(f"<div style='text-align:right;color:#555;font-size:12px'>"\
            f"Signed in as: <b>{u.get('name','Guest')}</b> "\
            f"({u.get('role','guest')}) &lt;{u.get('email','guest@sjcpl.local')}&gt;</div>",
            unsafe_allow_html=True)

# ----------------------------- Phase-2: RBAC & Company Meta -----------------------------
ACL_DEFAULT_SALT = "SJCPL-RBAC-2025-SALT"
REQ_HASH_SALT    = os.getenv("REQ_HASH_SALT", "SJCPL-PHASE2-HASH-SALT")
REQ_LOG_NAME     = "requirements_log.csv"
ACL_FILE_NAME    = "acl_users.csv"
ENABLED_TABS_FILE = "enabled_tabs.json"

DEFAULT_GH_REPO   = "dnyanesh57/TestRequest_Phase2"  # <--- your repo
DEFAULT_GH_FOLDER = "data"                           # folder inside repo
DEFAULT_GH_BRANCH = "master" 

# --- NEW: Configuration for Automatic File Loading ---
LOCAL_DATA_PATH = "data" # Create a folder named 'data' in the same directory as the script
GITHUB_API_URL = "https://api.github.com/repos/dnyanesh57/TestRequest_Phase2/contents/data" # Example: User's public repo

# ===== Company identity (no embedded logo) =====
COMPANY_DEFAULT = {
    "name": "SJ Contracts Pvt Ltd",
    "address_lines": [
        "SJ Contracts Pvt Ltd, 305 - 308 Amar Business Park",
        "Baner Road, Opp. Sadanand Hotel, Baner, Pune – 411045"
    ]
}
_NUMERIC_COLS = {"Initial_Qty","Remeasure_Add","Revised_Qty","Used_Qty","Remaining_Qty"}
def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _hmac_hex(msg: str, salt: str) -> str:
    return hmac.new(salt.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()

def _load_csv_safe(path: str) -> pd.DataFrame:
    if not os.path.exists(path): return pd.DataFrame()
    try:
        return pd.read_csv(path)
    except Exception:
        return pd.DataFrame()
import re

def _norm(s: str) -> str:
    """Normalize a string for fuzzy column matching: lowercase, strip, remove spaces and punctuation."""
    import re
    return re.sub(r'[\s\W_]+', '', str(s).lower().strip())

def best_col_fuzzy(df: pd.DataFrame, targets: list[str]) -> Optional[str]:
    """
    Return the first matching column from df for any of the 'targets',
    using:
      1) exact match
      2) startswith
      3) normalized equality
      4) normalized startswith
    """
    if df is None or df.empty or not isinstance(df.columns, pd.Index):
        return None

    cols = list(df.columns.astype(str))
    cols_norm = {c: _norm(c) for c in cols}

    for t in targets:
        if t in df.columns:
            return t

    for t in targets:
        for c in cols:
            if str(c).startswith(t):
                return c

    targets_norm = [_norm(t) for t in targets]
    for t in targets_norm:
        for c, cn in cols_norm.items():
            if cn == t:
                return c

    for t in targets_norm:
        for c, cn in cols_norm.items():
            if cn.startswith(t):
                return c
    return None

# Practical aliases frequently seen in exported WO files
_QUANTITY_ALIASES: dict[str, list[str]] = {
    # Initial
    "OD_Qty.": [
        "OD_Qty.", "OD_Qty", "Qty.", "Qty", "Quantity", "OD_Quantity", "BOQ Qty", "Original Qty",
        "Ordered Qty", "Order Qty"
    ],
    # Remeasure (+)
    "RMC_Qty..1": [
        "RMC_Qty..1", "Remeasure Qty", "Remeasure Qty.", "Remeasure (+)", "Addl Qty", "Addl Quantity",
        "Qty..1", "RMC Qty", "RMC Quantity", "Increase Qty"
    ],
    # Revised
    "RV_Qty..2": [
        "RV_Qty..2", "Revised Qty", "Revised Quantity", "Qty..2", "RV Qty", "Current Revised Qty",
        "Total Qty", "Total Revised Qty"
    ],
    # Used / Certified
    "CERT_Cert. Qty..1": [
        "CERT_Cert. Qty..1", "Certified Qty", "Cert. Qty", "Cert Qty", "Used Qty", "Used Quantity",
        "Certified Quantity", "Cumulative Certified Qty"
    ],
    # Remaining / Balance
    "RMN_Cert. Qty..2": [
        "RMN_Cert. Qty..2", "Remaining Qty", "Rem Qty", "Balance Qty", "Balance Quantity", "Pending Qty",
        "Cert. Qty..2", "To be certified"
    ],
}

def _save_csv_safe(df: pd.DataFrame, path: str):
    try: df.to_csv(path, index=False)
    except Exception: pass
_BASE_WIDTHS = {
    "Line_Key": 46,
    "OD_UOM": 46,
    "OD_Stage": 64,
    "Low_Tag": 42,
    "Subcontractor_Key": 140,
    "Project_Key": 140,
    "OI_Date": 80,
    "II_Title.1": 160,
    "OD_Description": 280,
}
_DEFAULT_TEXT_W = 100
_DEFAULT_NUM_W  = 72

def _is_numeric_col(col: str) -> bool:
    return (col in _NUMERIC_COLS) or col.endswith(("_Qty", "_Amount", "Qty", "Amount"))
def _col_width(col: str) -> int:
    if col in _BASE_WIDTHS:
        return _BASE_WIDTHS[col]
    return _DEFAULT_NUM_W if _is_numeric_col(col) else _DEFAULT_TEXT_W
def _ensure_acl_in_state():
    if "acl_df" in st.session_state:
        return

    df = pd.DataFrame() # Initialize df as an empty DataFrame

    # 1) Try DB first
    try: # Ensure Master Admin can always see the Admin tab
        if _user_is_master_admin() and "Admin" not in st.session_state.enabled_tabs:
            st.session_state.enabled_tabs.append("Admin") # This line might cause an error if enabled_tabs is not initialized
        # Also ensure other admin-only tabs are visible
        for t in ["Admin", "Email Drafts", "Export", "Requirements Registry"]:
            if _user_is_master_admin() and t not in st.session_state.enabled_tabs:
                st.session_state.enabled_tabs.append(t)

        from db_adapter import read_acl_df, write_acl_df  # already in your repo
        df = read_acl_df()
    except Exception:
        df = pd.DataFrame()  # swallow connection/operational errors and fall back

    # 2) Fall back to local CSV
    if df is None or df.empty:
        try:
            df = _load_csv_safe(ACL_FILE_NAME)
        except Exception:
            df = pd.DataFrame()

    # 3) Bootstrap default admin if still empty
    if df is None or df.empty:
        df = pd.DataFrame([{
            "email": "admin@sjcpl.local",
            "name": "Admin",
            "role": "master_admin",   # matches your current default
            "sites": "*",
            "tabs": "*",
            "can_raise": True,
            "can_view_registry": True,
            "can_export": True,
            "can_email_drafts": True,
            "password_hash": _sha256_hex("admin"),  # SHA256("admin")
        }])
        # Try to persist bootstrap to DB and CSV (best-effort)
        try:
            write_acl_df(df)
        except Exception:
            pass
        try:
            _save_csv_safe(df, ACL_FILE_NAME)
        except Exception:
            pass

    # 4) Backfill/normalize columns & types (keeps your compare logic)
    for c in ["can_raise", "can_view_registry", "can_export", "can_email_drafts"]:
        if c not in df.columns:
            df[c] = True
        df[c] = df[c].fillna(True).astype(bool)
    if "password_hash" not in df.columns or df["password_hash"].isna().any():
        df["password_hash"] = df.get("password_hash").fillna(_sha256_hex("admin"))

    st.session_state.acl_df = df

def _build_width_map(header_cols: list[str]) -> dict[str,int]:
    return {c: _col_width(c) for c in header_cols}

def _pack_groups(header_cols: list[str], width_map: dict[str,int], base_cols=("Line_Key","OD_Description")) -> list[list[str]]:
    base = [c for c in header_cols if c in base_cols]
    others = [c for c in header_cols if c not in base]
    groups = []
    while others:
        cur = base.copy()
        cur_w = sum(width_map.get(c, _DEFAULT_TEXT_W) for c in cur) or 0
        i = 0
        while i < len(others):
            w = width_map.get(others[i], _DEFAULT_TEXT_W)
            if cur_w + w <= _AVAIL_W:
                cur.append(others[i]); cur_w += w; i += 1
            else:
                break
        if i == 0:
            cur.append(others[0]); i = 1
        groups.append(cur)
        others = others[i:]
    if not groups:
        groups = [base or header_cols]
    return groups

def _to_cell(v, styles, is_num: bool):
    if is_num:
        try:
            f = float(v)
            return "" if pd.isna(f) else f"{f:,.2f}"
        except Exception:
            return ""
    s = "" if pd.isna(v) else str(v)
    s = s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
    return Paragraph(s, styles["Cell"])
def _pdf_lines_table_chunked(df_lines: pd.DataFrame, styles, title: str,
                             header_all: list[str], alert_col: str, threshold: float) -> list:
    story = []
    width_map = _build_width_map(header_all)
    groups = _pack_groups(header_all, width_map, base_cols=("Line_Key","OD_Description"))
    n_parts = len(groups)

    for idx, cols in enumerate(groups, start=1):
        part_title = title if n_parts == 1 else f"{title} (Part {idx}/{n_parts})"
        story.append(Paragraph(part_title, styles["Mini"]))

        data = [[(c if c else "") for c in cols]]
        col_widths = [width_map.get(c, _DEFAULT_TEXT_W) for c in cols]
        tstyle = _table_style()

        for j, c in enumerate(cols):
            if _is_numeric_col(c): tstyle.add("ALIGN", (j,1), (j,-1), "RIGHT")

        alert_idx = cols.index(alert_col) if alert_col in cols else None

        for i, (_, r) in enumerate(df_lines.iterrows(), start=1):
            row = [_to_cell(r.get(c, ""), styles, _is_numeric_col(c)) for c in cols]
            data.append(row)
            if alert_idx is not None:
                try:
                    val = float(r.get(alert_col, np.nan))
                    if pd.notna(val) and val < threshold:
                        tstyle.add("TEXTCOLOR", (alert_idx, i), (alert_idx, i), colors.red)
                except Exception:
                    pass

        tbl = Table(data, repeatRows=1, colWidths=col_widths, hAlign="LEFT", splitByRow=1)
        tbl.setStyle(tstyle)
        story += [tbl, Spacer(1, 8)]
    return story

@st.cache_data
def pdf_grouped_lines(
    items_f: pd.DataFrame,
    mode: str,                       # "all_projects" | "by_project" | "by_sub"
    selected: list[str] | None,
    line_cols: Sequence[str],
    title_suffix: str,
    alert_col: str,
    threshold: float,
) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=landscape(A4),
        leftMargin=_MARGINS["left"], rightMargin=_MARGINS["right"],
        topMargin=_MARGINS["top"], bottomMargin=_MARGINS["bottom"]
    )
    story = []; styles = _styles()

    story.append(Paragraph(f"SJCPL — Work Order Report {title_suffix}".strip(), styles["BrandTitle"]))
    story.append(Paragraph(
        "Tables are wrapped to fit the page width. If columns exceed the page, the table is split into parts, "
        "repeating Line # and Description. Low cells are shown in red.", styles["Small"]))
    story.append(Spacer(1, 6))

    def add_proj_block(dfp: pd.DataFrame, proj_name: str):
        story.append(Paragraph(f"Project: {proj_name}", styles["BrandH2"]))
        for wo, dwo in dfp.groupby("WO_Key", dropna=False):
            init = float(pd.to_numeric(dwo.get("Initial_Qty"), errors="coerce").sum())
            rmc  = float(pd.to_numeric(dwo.get("Remeasure_Add"), errors="coerce").sum())
            rev  = float(pd.to_numeric(dwo.get("Revised_Qty"), errors="coerce").sum())
            used = float(pd.to_numeric(dwo.get("Used_Qty"), errors="coerce").sum())
            rem  = float(pd.to_numeric(dwo.get("Remaining_Qty"), errors="coerce").sum())
            lines = int(dwo.get("Line_Key").nunique()) if "Line_Key" in dwo.columns else len(dwo)
            low   = int(dwo.get("Low_Flag", pd.Series(dtype=bool)).sum()) if "Low_Flag" in dwo.columns else 0
            story.append(Paragraph(
                f"WO: {wo}  —  Lines: {lines}  |  Initial: {init:.2f}  +Remeas: {rmc:.2f}  "
                f"Revised: {rev:.2f}  Used: {used:.2f}  Rem: {rem:.2f}  |  Low<{threshold:g}: {low}",
                styles["Small"]
            ))
            tbl_cols = [c for c in line_cols if c in dwo.columns]
            story.extend(_pdf_lines_table_chunked(
                dwo[tbl_cols], styles, "Line Details", tbl_cols, alert_col, threshold
            ))

    def add_sub_block(dfs: pd.DataFrame, sub_name: str):
        story.append(Paragraph(f"Subcontractor: {sub_name}", styles["BrandH2"]))
        for wo, dwo in dfs.groupby("WO_Key", dropna=False):
            init = float(pd.to_numeric(dwo.get("Initial_Qty"), errors="coerce").sum())
            rmc  = float(pd.to_numeric(dwo.get("Remeasure_Add"), errors="coerce").sum())
            rev  = float(pd.to_numeric(dwo.get("Revised_Qty"), errors="coerce").sum())
            used = float(pd.to_numeric(dwo.get("Used_Qty"), errors="coerce").sum())
            rem  = float(pd.to_numeric(dwo.get("Remaining_Qty"), errors="coerce").sum())
            lines = int(dwo.get("Line_Key").nunique()) if "Line_Key" in dwo.columns else len(dwo)
            low   = int(dwo.get("Low_Flag", pd.Series(dtype=bool)).sum()) if "Low_Flag" in dwo.columns else 0
            proj = str(dwo["Project_Key"].iloc[0]) if "Project_Key" in dwo.columns and len(dwo)>0 else ""
            story.append(Paragraph(
                f"WO: {wo}  —  Project: {proj}  —  Lines: {lines}  |  Initial: {init:.2f}  +Remeas: {rmc:.2f}  "
                f"Revised: {rev:.2f}  Used: {used:.2f}  Rem: {rem:.2f}  |  Low<{threshold:g}: {low}",
                styles["Small"]
            ))
            tbl_cols = [c for c in line_cols if c in dwo.columns]
            story.extend(_pdf_lines_table_chunked(
                dwo[tbl_cols], styles, "Line Details", tbl_cols, alert_col, threshold
            ))

    if mode == "all_projects":
        df = items_f.sort_values(["Project_Key","WO_Key","Line_Key"])
        for p in sorted(df["Project_Key"].dropna().unique().tolist()):
            add_proj_block(df[df["Project_Key"]==p], p); story.append(PageBreak())
    elif mode == "by_project":
        projs = selected or sorted(items_f["Project_Key"].dropna().unique())
        for p in projs:
            add_proj_block(items_f[items_f["Project_Key"]==p].sort_values(["WO_Key","Line_Key"]), p); story.append(PageBreak())
    else:  # by_sub
        subs = selected or sorted(items_f["Subcontractor_Key"].dropna().unique())
        for sc in subs:
            add_sub_block(items_f[items_f["Subcontractor_Key"]==sc].sort_values(["Project_Key","WO_Key","Line_Key"]), sc); story.append(PageBreak())

    doc.build(story)
    return buf.getvalue()
def _ensure_reqlog_in_state():
    if "reqlog_df" not in st.session_state:
        df = read_reqlog_df()  # <- DB, not CSV
        st.session_state.reqlog_df = ensure_registry_columns(df)

def _load_enabled_tabs():
    t = read_enabled_tabs() # if nothing saved, return base
    if not t:
        return ["Overview","Group: WO → Project","Work Order Explorer","Lifecycle","Subcontractor Summary","Browse","Status as on Date","Export","Email Drafts","Diagnostics","Raise Requirement","My Requests","Requirements Registry","Admin"]
    # always inject Admin for master admins later; here just return saved list
    return t if t else ["Overview","Group: WO → Project","Work Order Explorer","Lifecycle","Subcontractor Summary","Browse","Status as on Date","Export","Email Drafts","Diagnostics","Raise Requirement","My Requests","Requirements Registry","Admin"]

def _save_enabled_tabs(lst):
    write_enabled_tabs(lst)

if "enabled_tabs" not in st.session_state:
    st.session_state.enabled_tabs = _load_enabled_tabs()

def _login_block():
    _ensure_acl_in_state()
    is_logged_in = "user" in st.session_state
    with st.sidebar.expander("🔐 Login", expanded=not is_logged_in):
        emails = sorted(st.session_state.acl_df["email"].unique().tolist())
        email = st.selectbox("User", emails, index=0 if emails else None, key="rbac-email")
        pwd = st.text_input("Password", type="password", key="rbac-pwd")
        if st.button("Sign in", type="primary", key="rbac-go"):
            row = st.session_state.acl_df[st.session_state.acl_df["email"]==email].head(1)
            if not row.empty and _sha256_hex(pwd)==row.iloc[0]["password_hash"]:
                role_raw = str(row.iloc[0]["role"]).strip().lower()
                role_norm = "master_admin" if role_raw in ("admin","master_admin") else role_raw

                st.session_state.user = {
                    "email": email,
                    "name": row.iloc[0]["name"],
                    "role": role_norm,
                    "sites": row.iloc[0]["sites"],
                    "tabs": row.iloc[0]["tabs"],
                "can_raise": bool(row.iloc[0].get("can_raise", True)),
                "can_view_registry": bool(row.iloc[0].get("can_view_registry", True)),
                "can_export": bool(row.iloc[0].get("can_export", True)),
                "can_email_drafts": bool(row.iloc[0].get("can_email_drafts", True)),
                }
                st.success(f"Signed in as {row.iloc[0]['name']} ({row.iloc[0]['role']})")
                st.rerun()
            else:
                # Ensure admin tabs are visible for master admin
                if role_norm in ("master_admin", "admin"):
                    if "enabled_tabs" not in st.session_state:
                        st.session_state.enabled_tabs = _load_enabled_tabs()
                    must_have = ["Admin", "Email Drafts", "Export", "Requirements Registry"]
                    for t in must_have:
                        if t not in st.session_state.enabled_tabs:
                            st.session_state.enabled_tabs.append(t)
                    # Remove duplicates and save
                    st.session_state.enabled_tabs = list(dict.fromkeys(st.session_state.enabled_tabs))
                    _save_enabled_tabs(st.session_state.enabled_tabs)
                st.error("Invalid credentials")
        st.markdown("---")
        st.markdown("**Forgot your password?**")
        fp_email = st.text_input("Your email", key="fp-email")
        if st.button("Send Reset Link", key="fp-send"):
            if not fp_email:
                st.error("Enter your email.")
            else:
                try:
                    from db_adapter import start_password_reset
                    ok, msg, token, exp = start_password_reset(fp_email, ttl_minutes=30)
                    if ok and token:
                        base_url = st.secrets.get("app_base_url", "") or ""
                        reset_link = f"{base_url}?reset_token={token}" if base_url else f"?reset_token={token}"

                        html = f"""
                        <div style="font-family:Arial,Helvetica,sans-serif;color:#222">
                          <p>We received a request to reset your password.</p>
                          <p><a href="{reset_link}">Click here to reset your password</a></p>
                          <p>If you didn't request this, you can ignore this email.</p>
                          <p>This link expires at <b>{exp}</b> (UTC).</p>
                        </div>
                        """
                        subject = "SJCPL — Password Reset"
                        okm, emsg = send_email_via_smtp(fp_email, subject, html, None, None)
                        if okm:
                            st.success("Reset link sent to your email.")
                        else:
                            st.error(f"Failed to send email: {emsg}")
                    else:
                        st.error(msg)
                except Exception as e:
                    st.error(f"Error: {e}")

    if "user" not in st.session_state:
        st.warning("Please sign in to use the app.")
        st.stop()

def _role() -> str:
    return str(st.session_state.get("user", {}).get("role", "user"))

def _user_is_master_admin() -> bool:
    r = _role().lower()
    return r in ("master_admin", "admin")

def _user_is_site_admin() -> bool:
    return _role().lower() == "site_admin"

def _user_can(flag: str) -> bool:
    if _user_is_master_admin() or _user_is_site_admin():
        return True
    return bool(st.session_state.user.get(flag, False))

def _user_allowed_sites() -> list[str]:
    sites = st.session_state.user.get("sites","")
    if not sites or sites=="*": return ["*"]
    return [s.strip() for s in str(sites).split("|") if s.strip()]

def _user_allowed_tabs() -> list[str]:
    tabs = st.session_state.user.get("tabs","")
    if not tabs or tabs=="*": return ["*"]
    return [t.strip() for t in str(tabs).split("|") if t.strip()]

def has_tab_access(tab_label: str) -> bool:
    if tab_label == "Admin":
        return _user_is_master_admin()
    if tab_label == "Raise Requirement" and not _user_can("can_raise"):
        return False
    if tab_label == "Requirements Registry" and not _user_can("can_view_registry"):
        return False
    if tab_label == "Export" and not _user_can("can_export"):
        return False
    if tab_label == "Email Drafts" and not _user_can("can_email_drafts"):
        return False
    if _user_is_master_admin():
        return True
    tabs = _user_allowed_tabs()
    return True if "*" in tabs else (tab_label in tabs)

# >>> ADD: caption cleaner to drop leading "Line ..." and trailing "(Rem|Qty ...)"
import re

def _clean_line_caption(caption: str) -> str:
    if not caption:
        return ""
    s = str(caption).strip()

    # drop leading "Line xx — " (handles em dash or hyphen)
    s = re.sub(r'^\s*Line\s*[^—-]+[—-]\s*', '', s, flags=re.IGNORECASE)

    # drop any trailing parenthetical like "(Rem: 24.00)" "(Qty: 10)" "(Rem 12)"
    s = re.sub(r'\s*\((?:rem|qty)[^)]*\)\s*$', '', s, flags=re.IGNORECASE)

    # collapse extra spaces
    s = re.sub(r'\s+', ' ', s).strip()
    return s

def _clean_text_for_line(items_df: pd.DataFrame, proj: str, vendor: str, wo: str, line_key: str) -> str:
    sel = items_df[
        (items_df["Project_Key"].astype(str)==str(proj)) &
        (items_df["Subcontractor_Key"].astype(str)==str(vendor)) &
        (items_df["WO_Key"].astype(str)==str(wo)) &
        (items_df["Line_Key"].astype(str)==str(line_key))
    ].head(1)
    if sel.empty:
        return ""
    desc = str(sel.iloc[0].get("OD_Description","")).strip()
    # we build what the picker shows, then clean it (so the logic works no matter how you format it)
    raw_caption = f"Line {str(line_key).strip()} — {desc}"
    # (we purposely don't append (Rem: ...) here; cleaner handles it anyway)
    return _clean_line_caption(raw_caption)
DESC_ALIASES = [
    "OD_Description", "Description", "Item Description", "BOQ Item",
    "OD_BOQ Item", "Work Item Description", "Scope", "Item", "Narration",
    "II_Title.1", "OI_Title"
]

def resolve_desc_col(df: pd.DataFrame) -> Optional[str]:
    # try fuzzy first (you already have best_col_fuzzy)
    hit = best_col_fuzzy(df, DESC_ALIASES)
    if hit: return hit
    # fallback to your prefix-based best_col helper
    for c in DESC_ALIASES:
        b = best_col(df, c)
        if b: return b
    # last resort: any column with "desc" in its name
    for c in df.columns.astype(str):
        if "desc" in c.lower(): return c
    return None
def resolve_desc_col(df: pd.DataFrame) -> str | None:
    hit = best_col_fuzzy(df, DESC_ALIASES)
    if hit: return hit
    for c in DESC_ALIASES:
        b = best_col(df, c)
        if b: return b
    for c in df.columns.astype(str):
        if "desc" in c.lower(): return c
    return None

def get_selected_line_desc(items_df: pd.DataFrame, proj: str, vendor: str, wo: str, line_key: str) -> str:
    if not (proj and vendor and wo and line_key):
        return ""
    sel = items_df[
        (items_df["Project_Key"].astype(str)==str(proj)) &
        (items_df["Subcontractor_Key"].astype(str)==str(vendor)) &
        (items_df["WO_Key"].astype(str)==str(wo)) &
        (items_df["Line_Key"].astype(str)==str(line_key))
    ].head(1)
    if sel.empty:
        return ""
    dcol = resolve_desc_col(sel) or resolve_desc_col(items_df) or "OD_Description"
    raw  = str(sel.iloc[0].get(dcol, "")).strip()
    return _clean_line_caption(raw)

# Renamed to _is_tab_enabled to avoid recursion with the `is_enabled` function in the global scope
# >>> ADD: selection->form sync helper
def _prefill_from_line(items_df: pd.DataFrame, proj: str, vendor: str, wo: str, line_key: str) -> dict:
    """
    Returns sensible defaults (description, uom, stage, remaining) for a chosen line.
    If not found, returns blanks.
    """
    if not all([proj, vendor, wo, line_key]):
        return {"description":"", "uom":"", "stage":"", "remaining":float("nan"), "line_item": ""}

    sel = items_df[
        (items_df["Project_Key"].astype(str)==str(proj)) &
        (items_df["Subcontractor_Key"].astype(str)==str(vendor)) &
        (items_df["WO_Key"].astype(str)==str(wo)) &
        (items_df["Line_Key"].astype(str)==str(line_key))
    ].head(1)

    if sel.empty:
        return {"description":"", "uom":"", "stage":"", "remaining":float("nan"), "line_item": ""}

    r = sel.iloc[0]
    # original caption (what your picker shows): "Line 29.0 — <desc> (Rem: 24.00)"
    raw_caption = f"Line {str(r.get('Line_Key','')).strip()} — {str(r.get('OD_Description','')).strip()}"
    if pd.notna(r.get("Remaining_Qty")):
        try:
            rem = float(r.get("Remaining_Qty"))
            raw_caption = f"{raw_caption} (Rem: {rem:,.2f})"
        except Exception:
            pass

    cleaned = _clean_line_caption(raw_caption) # <- strip "Line ..." and "(Rem: ...)"

    return {
        "description": cleaned,                        # <<< now same as cleaned line text
        "uom":        str(r.get("OD_UOM","")).strip(),
        "stage":      str(r.get("OD_Stage","")).strip(),
        "remaining":  float(pd.to_numeric(r.get("Remaining_Qty"), errors="coerce")),
        "line_item":  cleaned                          # <<< keep in sync with description
    }
def _is_tab_enabled(tab_label: str) -> bool:
    # Safety net so Admin never disappears for master admins
    if _user_is_master_admin():
        # Ensure all admin-specific tabs are enabled for master admins
        for t in ["Admin", "Email Drafts", "Export", "Requirements Registry", "Approval List"]:
            if t not in st.session_state.enabled_tabs: st.session_state.enabled_tabs.append(t)
    return tab_label in st.session_state.enabled_tabs

def can_view(tab_label: str) -> bool:
    return _is_tab_enabled(tab_label) and has_tab_access(tab_label)


# ----------------------------- Helpers (Phase-1) -----------------------------
def coerce_number(s: pd.Series) -> pd.Series:
    """
    Robust numeric coercion:
    - Trims, removes NBSP, collapses spaces
    - Converts parentheses to negatives: (123.45) -> -123.45
    - Removes thousands separators
    - Keeps digits, dot, and minus only
    """
    if s.dtype.kind in "biufc":
        return s.astype(float)

    # to string
    s = s.astype(str)

    # normalize whitespace & NBSP
    s = s.str.replace("\u00a0", " ", regex=False).str.strip()
    s = s.str.replace(r"\s+", " ", regex=True)

    # parentheses negative: "(123.45)" -> "-123.45"
    s = s.str.replace(r"^\((.*)\)$", r"-\1", regex=True)

    # drop common prefixes/suffixes (units/labels around numbers)
    # keep a conservative approach: strip everything except digits, dot, minus and comma
    s = s.str.replace(r"[^0-9\.\-,]", "", regex=True)

    # if there are both comma and dot, treat comma as thousands sep; if only comma, treat as decimal
    has_comma = s.str.contains(",", regex=False, na=False)
    has_dot   = s.str.contains(r"\.", regex=True, na=False)

    # only comma and no dot -> comma is decimal
    s = s.mask(has_comma & (~has_dot), s.str.replace(",", ".", regex=False))

    # both comma and dot or only dot -> comma is thousands separator
    s = s.str.replace(",", "", regex=False)

    return pd.to_numeric(s, errors="coerce")


def coerce_date(s: pd.Series) -> pd.Series:
    return pd.to_datetime(s, errors="coerce", dayfirst=True, infer_datetime_format=True)

def dedupe_columns(cols: List[str]) -> List[str]:
    seen = {}
    out = []
    for c in map(str, cols):
        if c in seen: seen[c]+=1; out.append(f"{c}.{seen[c]}")
        else: seen[c]=0; out.append(c)
    return out

def present_cols(df: pd.DataFrame, candidates: Sequence[str]) -> List[str]:
    return [c for c in candidates if c in df.columns]

@st.cache_data
def group_totals(df: pd.DataFrame) -> Tuple[float,float,float,float,float,int,int]:
    if df.empty: return (0.0,0.0,0.0,0.0,0.0,0,0)
    return (float(df["Initial_Qty"].sum()),
            float(df["Remeasure_Add"].sum()),
            float(df["Revised_Qty"].sum()),
            float(df["Used_Qty"].sum()),
            float(df["Remaining_Qty"].sum()),
            int(df["Line_Key"].nunique()),
            int(df["Low_Flag"].sum()) if "Low_Flag" in df.columns else 0)

@st.cache_data
def annotate_low(df: pd.DataFrame, metric: str, threshold: float) -> pd.DataFrame:
    df = df.copy()
    if metric not in df.columns: df[metric] = np.nan
    df["Low_Flag"] = df[metric] < threshold
    df["Low_Tag"]  = np.where(df["Low_Flag"], "🔴 Low", "")
    return df
_PAGE_SIZE = landscape(A4)
_MARGINS = dict(left=18, right=18, top=18, bottom=18)
_AVAIL_W = _PAGE_SIZE[0] - _MARGINS["left"] - _MARGINS["right"]
# ---------------------- Column Mapping ----------------------
PREFIX_MAPPING: Dict[str, List[str]] = {
    "OI_": [
        'Project','L1 Analysis Code','L2 Analysis Code','Unnamed: 3','Unnamed: 4',
        'L3 Analysis Code','Unnamed: 6','L4 Analysis Code','L5 Analysis Code','Step Code',
        'Step Name','Unnamed: 11','Unnamed: 12','Ref. #','Date','External Ref. #',
        'Subcontractor Code','Subcontractor Name','Trade','Title','Originator','Status',
        'Finalisation Status','Currency','Valuation Applicable','TA Ref. #','TA Revision #'
    ],
    "II_": [
        'Ref. #.1','Date.1','Title.1','Originator.1','Instruction Status',
        'Finalisation Status.1','Approval Status','Nature Code','Nature Name',
        'Client Change','Client Change Type Code','Client Change Type Name',
        'Contract Variation','CVR Variation Category - Inst Code',
        'CVR Variation Category - Inst Name','TA Ref. #.1','TA Revision #.1','Claim Amount'
    ],
    "OD_": [
        'Line #','Line Type','BOQ Item','Rate Only','Internal Item','Trade.1',
        'Description','UOM','Qty.','Rate','Amount','Remarks','Contract Item Ref. #',
        'IBR Item Ref. #','Cost Code','Cost Code Description','Cost Head Code',
        'Cost Head Description','Prime Activity Code','Prime Activity Name','Phase',
        'Block','Plot','VAT Type','VAT Code','Stage'
    ],
    "RMC_": ['Qty..1','Amount.1'],
    "RV_":  ['Qty..2','Amount.2'],
    "CERT_": ['Cert. Qty..1','Cert. Amount.1'],
    "RMN_":  ['Cert. Qty..2','Cert. Amount.2'],
}
REVERSE_MAP = {orig: f"{pref}{orig}" for pref, group in PREFIX_MAPPING.items() for orig in group}

def rename_with_prefix(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy() # 1) Stabilize headers (strip + dedupe)
    raw_cols = [str(c).strip() for c in df.columns]
    raw_cols = dedupe_columns(raw_cols)
    # 2) Apply mapping where we have it; keep others as-is
    new_cols = [REVERSE_MAP.get(c, c) for c in raw_cols]
    df.columns = new_cols

    # GUARANTEE these exist (backfills)
    if "OD_Description" not in df.columns:
        for alt in ["Description", "Item Description", "BOQ Item"]:
            if alt in df.columns:
                df["OD_Description"] = df[alt]
                break
        else:
            df["OD_Description"] = ""

    if "OD_UOM" not in df.columns and "UOM" in df.columns:
        df["OD_UOM"] = df["UOM"]
    if "OD_Stage" not in df.columns and "Stage" in df.columns:
        df["OD_Stage"] = df["Stage"]

    return df

    # 3) Ensure key downstream columns exist (aliases/backfills)
    # Guarantee OD_Description exists (many exports name it just "Description") # This block is duplicated
    if "OD_Description" not in df.columns:
        # try common alternates that may have slipped through
        for alt in ["Description", "Item Description", "BOQ Item"]:
            if alt in df.columns:
                df["OD_Description"] = df[alt]
                break
        else:
            # if nothing found, create empty so downstream doesn't break
            df["OD_Description"] = ""

    # UOM / Stage often used downstream too
    if "OD_UOM" not in df.columns and "UOM" in df.columns:
        df["OD_UOM"] = df["UOM"]
    if "OD_Stage" not in df.columns and "Stage" in df.columns:
        df["OD_Stage"] = df["Stage"]

    return df
def find_qty_source(df: pd.DataFrame, canonical: str) -> str:
    """
    Given a canonical key like 'OD_Qty.' returns the actual column name found in df using fuzzy matching over known aliases.
    If nothing is found, returns the canonical string (which upstream code guards by creating the column if missing).
    """
    aliases = _QUANTITY_ALIASES.get(canonical, [canonical])
    hit = best_col_fuzzy(df, aliases)
    return hit or canonical

def best_col(df: pd.DataFrame, base: str) -> str | None:
    if base in df.columns: return base
    cand = [c for c in df.columns if c.startswith(base)]
    if cand: return cand[0]
    if "_" in base:
        raw = base.split("_", 1)[1]
        if raw in df.columns: return raw
        cand2 = [c for c in df.columns if c.startswith(raw)]
        if cand2: return cand2[0]
    return None

def get_most_recent_file(directory: str) -> str | None:
    try:
        files = [os.path.join(directory, f) for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
        if not files:
            return None
        return max(files, key=os.path.getmtime)
    except Exception:
        return None
# --- GitHub data helpers ---
# --- GitHub data helpers (improved diagnostics + raw fallback) ---
def _gh_headers():
    tok = (st.secrets.get("github", {}) or {}).get("token")
    h = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "SJCPL-WO-Dashboard",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h

def gh_list_folder(repo: str, folder: str, branch: str) -> list[dict]:
    """
    Lists CSV/XLSX files under the given folder via GitHub Contents API.
    Raises with a descriptive error if anything goes wrong.
    """
    url = f"https://api.github.com/repos/{repo}/contents/{folder}"
    try:
        r = requests.get(url, headers=_gh_headers(), params={"ref": branch}, timeout=20)
        if r.status_code != 200:
            # Bubble up readable diagnostics in UI
            try:
                detail = r.json().get("message", "")
            except Exception:
                detail = r.text[:200]
            raise RuntimeError(f"GitHub list error {r.status_code}: {detail} (repo={repo}, folder={folder}, branch={branch})")
        data = r.json()
        if not isinstance(data, list):
            raise RuntimeError(f"Unexpected response for contents list: {type(data)}")
        return [x for x in data if x.get("type") == "file" and x["name"].lower().endswith((".csv",".xlsx",".xls"))]
    except RuntimeError as e:
        if "API rate limit exceeded" in str(e):
            st.error("GitHub API rate limit exceeded. Please add a GitHub token to your secrets to increase the rate limit.")
            st.info("1. Create a file named `.streamlit/secrets.toml` in your project directory.\n2. Add the following content to the file:\n```toml\n[github]\ntoken = \"YOUR_GITHUB_TOKEN\"\n```\n3. Replace `YOUR_GITHUB_TOKEN` with a GitHub personal access token.")
        raise e

def gh_last_commit_iso(repo: str, path: str, branch: str) -> str:
    url = f"https://api.github.com/repos/{repo}/commits"
    r = requests.get(url, headers=_gh_headers(), params={"path": path, "sha": branch, "per_page": 1}, timeout=20)
    if r.status_code != 200:
        return ""
    js = r.json()
    try:
        return js[0]["commit"]["committer"]["date"]
    except Exception:
        return ""

def gh_pick_latest(repo: str, folder: str, branch: str) -> dict|None:
    items = gh_list_folder(repo, folder, branch)
    if not items:
        return None
    enriched = []
    for it in items:
        it["_last"] = gh_last_commit_iso(repo, f"{folder}/{it['name']}", branch)
        enriched.append(it)
    enriched.sort(key=lambda x: (x.get("_last") or "", x["name"]), reverse=True)
    return enriched[0]

def gh_download(download_url: str) -> bytes:
    r = requests.get(download_url, headers=_gh_headers(), timeout=40)
    if r.status_code != 200:
        try:
            detail = r.json().get("message", "")
        except Exception:
            detail = r.text[:200]
        raise RuntimeError(f"GitHub download error {r.status_code}: {detail}")
    return r.content

def load_table_from_bytes(data: bytes, filename: str) -> pd.DataFrame:
    name = filename.lower(); bio = io.BytesIO(data); bio.name = filename
    try:
        if name.endswith(".csv"):
            # If your CSVs do NOT have two junk rows at the top, change skiprows=2 -> 0
            return pd.read_csv(bio, encoding="latin1", engine="python", skiprows=2)
        return pd.read_excel(bio, skiprows=2, engine="openpyxl")
    except Exception as e:
        st.error(f"GitHub file parse error for {filename}: {e}")
        return pd.DataFrame()

def _raw_url(repo: str, branch: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/{branch}/{path}"

def try_load_latest_from_github(repo: str, folder: str, branch: str) -> tuple[pd.DataFrame, str]:
    """
    1) Use Contents API to find most-recent CSV/XLSX by last commit.
    2) Download via the provided 'download_url'.
    3) If listing fails, try raw.githubusercontent.com with common names.
    """
    try:
        meta = gh_pick_latest(repo, folder, branch)
        if meta:
            raw = gh_download(meta["download_url"])
            return (load_table_from_bytes(raw, meta["name"]), f"GitHub: {meta['name']}")
        # No CSV/XLSX in the folder
        raise RuntimeError(f"No CSV/XLSX found in '{folder}' on branch '{branch}'.")
    except Exception as e:
        # Fallback: raw URL with common names (helps when Contents API is rate-limited)
        common_names = ["work_orders.csv", "wo.csv", "data.csv", "items.csv", "work_orders.xlsx", "wo.xlsx"]
        for fname in common_names:
            try:
                url = _raw_url(repo, branch, f"{folder.rstrip('/')}/{fname}")
                r = requests.get(url, headers={"User-Agent":"SJCPL-WO-Dashboard"}, timeout=20)
                if r.status_code == 200:
                    return (load_table_from_bytes(r.content, fname), f"GitHub (raw): {fname}")
            except Exception:
                pass
        # Surface the real reason
        st.error(f"GitHub load failed: {e}")
        return (pd.DataFrame(), "")

# ---------------------- Load ----------------------
# 1) Stop hitting GitHub on every rerun
# Only fetch from GitHub when the admin presses a button; otherwise reuse what’s already loaded.
# after login/bootstrap:
if "_raw_df_cache" not in st.session_state:
    st.session_state._raw_df_cache = None
    st.session_state._raw_df_meta  = ""

# 2) Cache expensive transforms with explicit keys
# compute_items() depends only on raw_df content. Hash the bytes so the cache is stable.
@st.cache_data(show_spinner=False, max_entries=3)
def _df_signature(df: pd.DataFrame) -> str:
    # robust-ish signature for cache key
    h = hashlib.sha1()
    h.update(str(df.shape).encode())
    h.update("|".join(df.columns.astype(str)).encode())
    h.update(pd.util.hash_pandas_object(df.head(50), index=False).values.tobytes())
    return h.hexdigest()
def load_table(upload) -> pd.DataFrame:
    if upload is None: return pd.DataFrame()
    name = upload.name.lower() # This function is duplicated
    try:
        if name.endswith(".csv"):
            df = pd.read_csv(upload, encoding="latin1", engine="python", skiprows=2)
        elif name.endswith((".xlsx", ".xls")):
            df = pd.read_excel(upload, skiprows=2, engine="openpyxl")
        else:
            st.error("Please upload a .csv or .xlsx file."); return pd.DataFrame()
        return df
    except Exception as e:
        st.error(f"Error loading file: {e}")
        return pd.DataFrame()

# ---------------------- Transform (robust) ----------------------
# 6) Vectorize types early (smaller & faster)
# Cut memory + speed up groupbys.
def _shrink(df: pd.DataFrame) -> pd.DataFrame: # This function is duplicated
    df = df.copy()
    num_cols = ["Initial_Qty","Remeasure_Add","Revised_Qty","Used_Qty","Remaining_Qty"]
    for c in num_cols:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce").astype("float32")
    cat_cols = ["Project_Key","Subcontractor_Key","WO_Key","OD_UOM","OD_Stage"]
    for c in cat_cols:
        if c in df.columns:
            df[c] = df[c].astype("category")
    return df
@st.cache_data
def compute_items(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty: return df # This function is duplicated

    col_ref  = best_col(df, "OI_Ref. #") or "OI_Ref. #"
    col_proj = best_col(df, "OI_Project") or "OI_Project"
    col_subc = best_col(df, "OI_Subcontractor Name") or "OI_Subcontractor Name"
    col_date = best_col(df, "OI_Date") or "OI_Date"
    col_lt   = best_col(df, "OD_Line Type") or "OD_Line Type"
    col_ln   = best_col(df, "OD_Line #") or "OD_Line #"

    for need in [col_ref, col_proj, col_subc, col_lt, col_ln, col_date]:
        if need not in df.columns: df[need] = np.nan
    df = rename_with_prefix(df)
    lt_series = df[col_lt].astype(str).str.strip().str.lower()
    items = df.copy()  # default (some exports omit clear 'Item' tagging)
    mask_item = (
        lt_series.eq("item")
    |   lt_series.str.contains(r"\bitem\b", na=False)
    |   lt_series.str.contains(r"boq", na=False)
)
    if mask_item.any():
        items = df[mask_item].copy()

    # robust, alias-aware resolution
    src_initial = find_qty_source(items, "OD_Qty.")
    src_rmc     = find_qty_source(items, "RMC_Qty..1")
    src_rv      = find_qty_source(items, "RV_Qty..2")
    src_used    = find_qty_source(items, "CERT_Cert. Qty..1")
    src_rmn     = find_qty_source(items, "RMN_Cert. Qty..2")


    for c in [src_initial, src_rmc, src_rv, src_used, src_rmn]:
        if c not in items.columns: items[c] = np.nan

    items["Initial_Qty"]   = coerce_number(items[src_initial]).fillna(0.0)
    items["Remeasure_Add"] = coerce_number(items[src_rmc]).fillna(0.0)
    rv_tmp                 = coerce_number(items[src_rv])
    items["Revised_Qty"]   = np.where(rv_tmp.notna(), rv_tmp, items["Initial_Qty"] + items["Remeasure_Add"])
    items["Used_Qty"]      = coerce_number(items[src_used]).fillna(0.0)
    rmn_tmp                = coerce_number(items[src_rmn])
    items["Remaining_Qty"] = np.where(rmn_tmp.notna(), rmn_tmp, np.maximum(items["Revised_Qty"] - items["Used_Qty"], 0.0))

    if col_date in items.columns: items[col_date] = coerce_date(items[col_date])
    if best_col(items, "II_Date.1"):
        col_iidate = best_col(items, "II_Date.1")
        items[col_iidate] = coerce_date(items[col_iidate])

    for c in [
        "OD_Description","OD_UOM","OD_Rate","OD_Amount","OD_Remarks","OD_BOQ Item","OD_Internal Item","OD_Rate Only",
        "OD_Cost Code","OD_Cost Code Description","OD_Cost Head Code","OD_Cost Head Description",
        "OD_Prime Activity Code","OD_Prime Activity Name","OD_Phase","OD_Block","OD_Plot","OD_VAT Type","OD_VAT Code","OD_Stage",
        "OI_Title","II_Title.1","II_Nature Name","II_Approval Status","II_Instruction Status","II_Finalisation Status.1","II_Claim Amount"
    ]:
        if best_col(items, c) and best_col(items, c) != c:
            items[c] = items[best_col(items, c)]
        if c not in items.columns: items[c] = np.nan

    items["WO_Key"]           = items[col_ref].astype(str).str.strip()
    items["Project_Key"]      = items[col_proj].astype(str).str.strip()
    items["Subcontractor_Key"]= items[col_subc].astype(str).str.strip()
    items["Line_Key"]         = items[col_ln].astype(str).str.strip()
    if items["Line_Key"].isna().all() or (items["Line_Key"].astype(str).str.strip()=="").all():
        items["Line_Key"] = items.groupby(["Project_Key","WO_Key"]).cumcount()+1
        items["Line_Key"] = items["Line_Key"].astype(str)

    items.__dict__["_lt_filter_note"] = (
        "eq('Item')" if (lt_series.eq("item").any())
        else ("contains('item')" if (lt_series.str.contains("item", na=False).any()) else "no-filter (fallback)")
    )
    return items

@st.cache_data
def wo_summary(items: pd.DataFrame) -> pd.DataFrame:
    if items.empty: return items # This function is duplicated
    return items.groupby(["WO_Key","Project_Key","Subcontractor_Key"], dropna=False).agg(
        Lines=("Line_Key","nunique"),
        Initial_Qty=("Initial_Qty","sum"),
        Remeasure_Add=("Remeasure_Add","sum"),
        Revised_Qty=("Revised_Qty","sum"),
        Used_Qty=("Used_Qty","sum"),
        Remaining_Qty=("Remaining_Qty","sum"),
    ).reset_index()

# 4) Avoid re-grouping massive DataFrames for every expander
# Precompute once per filter and reuse.
@st.cache_data(show_spinner=False, max_entries=10)
def pre_aggregations(df: pd.DataFrame):
    if df.empty: # This function is duplicated
        return pd.DataFrame(), pd.DataFrame(), pd.DataFrame()
    wo = wo_summary(df)
    proj = wo.groupby("Project_Key", dropna=False)[["Initial_Qty","Remeasure_Add","Revised_Qty","Used_Qty","Remaining_Qty"]].sum().reset_index()
    sub  = wo.groupby("Subcontractor_Key", dropna=False)[["Initial_Qty","Remeasure_Add","Revised_Qty","Used_Qty","Remaining_Qty"]].sum().reset_index()
    return wo, proj, sub

# ---------------------- PDF helpers ----------------------
@st.cache_resource
def _styles():
    styles = getSampleStyleSheet() # This function is duplicated
    styles.add(ParagraphStyle(name="BrandTitle", fontName="Helvetica-Bold", fontSize=14, textColor=colors.HexColor(BRAND_BLACK), spaceAfter=6))
    styles.add(ParagraphStyle(name="BrandH2", fontName="Helvetica-Bold", fontSize=12, textColor=colors.HexColor(BRAND_BLUE), spaceAfter=4))
    styles.add(ParagraphStyle(name="Small", fontName="Helvetica", fontSize=8, textColor=colors.black, leading=10))
    styles.add(ParagraphStyle(name="Mini", fontName="Helvetica", fontSize=7, textColor=colors.black, leading=9))
    styles.add(ParagraphStyle(name="Cell", fontName="Helvetica", fontSize=8, leading=10, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="CellBold", parent=styles["Cell"], fontName="Helvetica-Bold"))
        # === Emphasis styles for Reference & Integrity ===
    styles.add(ParagraphStyle(
        name="MetaLabel",
        parent=styles["Small"],
        fontName="Helvetica-Bold",
        fontSize=12,
        textColor=colors.HexColor(BRAND_BLACK),
        leading=14,
        spaceAfter=0,
    ))

# ----------------------------- Helpers (Phase-1) -----------------------------
def coerce_number(s: pd.Series) -> pd.Series:
    """
    Robust numeric coercion:
    - Trims, removes NBSP, collapses spaces
    - Converts parentheses to negatives: (123.45) -> -123.45
    - Removes thousands separators
    - Keeps digits, dot, and minus only
    """
    if s.dtype.kind in "biufc":
        return s.astype(float)

    # to string
    s = s.astype(str)

    # normalize whitespace & NBSP
    s = s.str.replace("\u00a0", " ", regex=False).str.strip()
    s = s.str.replace(r"\s+", " ", regex=True)

    # parentheses negative: "(123.45)" -> "-123.45"
    s = s.str.replace(r"^\((.*)\)$", r"-\1", regex=True)

    # drop common prefixes/suffixes (units/labels around numbers)
    # keep a conservative approach: strip everything except digits, dot, minus and comma
    s = s.str.replace(r"[^0-9\.\-,]", "", regex=True)

    # if there are both comma and dot, treat comma as thousands sep; if only comma, treat as decimal
    has_comma = s.str.contains(",", regex=False, na=False)
    has_dot   = s.str.contains(r"\.", regex=True, na=False)

    # only comma and no dot -> comma is decimal
    s = s.mask(has_comma & (~has_dot), s.str.replace(",", ".", regex=False))

    # both comma and dot or only dot -> comma is thousands separator
    s = s.str.replace(",", "", regex=False)

    return pd.to_numeric(s, errors="coerce")


def coerce_date(s: pd.Series) -> pd.Series:
    return pd.to_datetime(s, errors="coerce", dayfirst=True, infer_datetime_format=True)

def dedupe_columns(cols: List[str]) -> List[str]:
    seen = {}; out = []
    for c in cols:
        if c in seen: seen[c]+=1; out.append(f"{c}.{seen[c]}")
        else: seen[c]=0; out.append(c)
    return out

def present_cols(df: pd.DataFrame, candidates: Sequence[str]) -> List[str]:
    return [c for c in candidates if c in df.columns]

@st.cache_data
def group_totals(df: pd.DataFrame) -> Tuple[float,float,float,float,float,int,int]:
    if df.empty: return (0.0,0.0,0.0,0.0,0.0,0,0)
    return (float(df["Initial_Qty"].sum()),
            float(df["Remeasure_Add"].sum()),
            float(df["Revised_Qty"].sum()),
            float(df["Used_Qty"].sum()),
            float(df["Remaining_Qty"].sum()),
            int(df["Line_Key"].nunique()),
            int(df["Low_Flag"].sum()) if "Low_Flag" in df.columns else 0)

@st.cache_data
def annotate_low(df: pd.DataFrame, metric: str, threshold: float) -> pd.DataFrame:
    df = df.copy()
    if metric not in df.columns: df[metric] = np.nan
    df["Low_Flag"] = df[metric] < threshold
    df["Low_Tag"]  = np.where(df["Low_Flag"], "🔴 Low", "")
    return df
_PAGE_SIZE = landscape(A4)
_MARGINS = dict(left=18, right=18, top=18, bottom=18)
_AVAIL_W = _PAGE_SIZE[0] - _MARGINS["left"] - _MARGINS["right"]
# ---------------------- Column Mapping ----------------------
PREFIX_MAPPING: Dict[str, List[str]] = {
    "OI_": [
        'Project','L1 Analysis Code','L2 Analysis Code','Unnamed: 3','Unnamed: 4',
        'L3 Analysis Code','Unnamed: 6','L4 Analysis Code','L5 Analysis Code','Step Code',
        'Step Name','Unnamed: 11','Unnamed: 12','Ref. #','Date','External Ref. #',
        'Subcontractor Code','Subcontractor Name','Trade','Title','Originator','Status',
        'Finalisation Status','Currency','Valuation Applicable','TA Ref. #','TA Revision #'
    ],
    "II_": [
        'Ref. #.1','Date.1','Title.1','Originator.1','Instruction Status',
        'Finalisation Status.1','Approval Status','Nature Code','Nature Name',
        'Client Change','Client Change Type Code','Client Change Type Name',
        'Contract Variation','CVR Variation Category - Inst Code',
        'CVR Variation Category - Inst Name','TA Ref. #.1','TA Revision #.1','Claim Amount'
    ],
    "OD_": [
        'Line #','Line Type','BOQ Item','Rate Only','Internal Item','Trade.1',
        'Description','UOM','Qty.','Rate','Amount','Remarks','Contract Item Ref. #',
        'IBR Item Ref. #','Cost Code','Cost Code Description','Cost Head Code',
        'Cost Head Description','Prime Activity Code','Prime Activity Name','Phase',
        'Block','Plot','VAT Type','VAT Code','Stage'
    ],
    "RMC_": ['Qty..1','Amount.1'],
    "RV_":  ['Qty..2','Amount.2'],
    "CERT_": ['Cert. Qty..1','Cert. Amount.1'],
    "RMN_":  ['Cert. Qty..2','Cert. Amount.2'],
}
REVERSE_MAP = {c: f"{p}{c}" for p, cols in PREFIX_MAPPING.items() for c in cols}

def rename_with_prefix(df: pd.DataFrame) -> pd.DataFrame:
    raw_cols = dedupe_columns([str(c).strip() for c in df.columns])
    df.columns = [REVERSE_MAP.get(c, c) for c in raw_cols]
    return df
def find_qty_source(df: pd.DataFrame, canonical: str) -> str:
    """
    Given a canonical key like 'OD_Qty.' returns the actual column name
    found in df using fuzzy matching over known aliases.
    If nothing is found, returns the canonical string (which upstream code
    guards by creating the column if missing).
    """
    aliases = _QUANTITY_ALIASES.get(canonical, [canonical])
    hit = best_col_fuzzy(df, aliases)
    return hit or canonical

def best_col(df: pd.DataFrame, base: str) -> str | None:
    if base in df.columns: return base
    cand = [c for c in df.columns if c.startswith(base)]
    if cand: return cand[0]
    if "_" in base:
        raw = base.split("_", 1)[1]
        if raw in df.columns: return raw
        cand2 = [c for c in df.columns if c.startswith(raw)]
        if cand2: return cand2[0]
    return None

def get_most_recent_file(directory: str) -> str | None:
    try:
        files = [os.path.join(directory, f) for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
        if not files:
            return None
        return max(files, key=os.path.getmtime)
    except Exception:
        return None
# --- GitHub data helpers ---
# --- GitHub data helpers (improved diagnostics + raw fallback) ---
def _gh_headers():
    tok = (st.secrets.get("github", {}) or {}).get("token")
    h = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "SJCPL-WO-Dashboard",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h

def gh_list_folder(repo: str, folder: str, branch: str) -> list[dict]:
    """
    Lists CSV/XLSX files under the given folder via GitHub Contents API.
    Raises with a descriptive error if anything goes wrong.
    """
    url = f"https://api.github.com/repos/{repo}/contents/{folder}"
    try:
        r = requests.get(url, headers=_gh_headers(), params={"ref": branch}, timeout=20)
        if r.status_code != 200:
            # Bubble up readable diagnostics in UI
            try:
                detail = r.json().get("message", "")
            except Exception:
                detail = r.text[:200]
            raise RuntimeError(f"GitHub list error {r.status_code}: {detail} (repo={repo}, folder={folder}, branch={branch})")
        data = r.json()
        if not isinstance(data, list):
            raise RuntimeError(f"Unexpected response for contents list: {type(data)}")
        return [x for x in data if x.get("type") == "file" and x["name"].lower().endswith((".csv",".xlsx",".xls"))]
    except RuntimeError as e:
        if "API rate limit exceeded" in str(e):
            st.error("GitHub API rate limit exceeded. Please add a GitHub token to your secrets to increase the rate limit.")
            st.info("1. Create a file named `.streamlit/secrets.toml` in your project directory.\n2. Add the following content to the file:\n```toml\n[github]\ntoken = \"YOUR_GITHUB_TOKEN\"\n```\n3. Replace `YOUR_GITHUB_TOKEN` with a GitHub personal access token.")
        raise e

def gh_last_commit_iso(repo: str, path: str, branch: str) -> str:
    url = f"https://api.github.com/repos/{repo}/commits"
    r = requests.get(url, headers=_gh_headers(), params={"path": path, "sha": branch, "per_page": 1}, timeout=20)
    if r.status_code != 200:
        return ""
    js = r.json()
    try:
        return js[0]["commit"]["committer"]["date"]
    except Exception:
        return ""

def gh_pick_latest(repo: str, folder: str, branch: str) -> dict|None:
    items = gh_list_folder(repo, folder, branch)
    if not items:
        return None
    enriched = []
    for it in items:
        it["_last"] = gh_last_commit_iso(repo, f"{folder}/{it['name']}", branch)
        enriched.append(it)
    enriched.sort(key=lambda x: (x.get("_last") or "", x["name"]), reverse=True)
    return enriched[0]

def gh_download(download_url: str) -> bytes:
    r = requests.get(download_url, headers=_gh_headers(), timeout=40)
    if r.status_code != 200:
        try:
            detail = r.json().get("message", "")
        except Exception:
            detail = r.text[:200]
        raise RuntimeError(f"GitHub download error {r.status_code}: {detail}")
    return r.content

def load_table_from_bytes(data: bytes, filename: str) -> pd.DataFrame:
    name = filename.lower(); bio = io.BytesIO(data); bio.name = filename
    try:
        if name.endswith(".csv"):
            # If your CSVs do NOT have two junk rows at the top, change skiprows=2 -> 0
            return pd.read_csv(bio, encoding="latin1", engine="python", skiprows=2)
        return pd.read_excel(bio, skiprows=2, engine="openpyxl")
    except Exception as e:
        st.error(f"GitHub file parse error for {filename}: {e}")
        return pd.DataFrame()

def _raw_url(repo: str, branch: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/{branch}/{path}"

def try_load_latest_from_github(repo: str, folder: str, branch: str) -> tuple[pd.DataFrame, str]:
    """
    1) Use Contents API to find most-recent CSV/XLSX by last commit.
    2) Download via the provided 'download_url'.
    3) If listing fails, try raw.githubusercontent.com with common names.
    """
    try:
        meta = gh_pick_latest(repo, folder, branch)
        if meta:
            raw = gh_download(meta["download_url"])
            return (load_table_from_bytes(raw, meta["name"]), f"GitHub: {meta['name']}")
        # No CSV/XLSX in the folder
        raise RuntimeError(f"No CSV/XLSX found in '{folder}' on branch '{branch}'.")
    except Exception as e:
        # Fallback: raw URL with common names (helps when Contents API is rate-limited)
        common_names = ["work_orders.csv", "wo.csv", "data.csv", "items.csv", "work_orders.xlsx", "wo.xlsx"]
        for fname in common_names:
            try:
                url = _raw_url(repo, branch, f"{folder.rstrip('/')}/{fname}")
                r = requests.get(url, headers={"User-Agent":"SJCPL-WO-Dashboard"}, timeout=20)
                if r.status_code == 200:
                    return (load_table_from_bytes(r.content, fname), f"GitHub (raw): {fname}")
            except Exception:
                pass
        # Surface the real reason
        st.error(f"GitHub load failed: {e}")
        return (pd.DataFrame(), "")

# ---------------------- Load ----------------------
# 1) Stop hitting GitHub on every rerun
# Only fetch from GitHub when the admin presses a button; otherwise reuse what’s already loaded.
# after login/bootstrap:
if "_raw_df_cache" not in st.session_state:
    st.session_state._raw_df_cache = None
    st.session_state._raw_df_meta  = ""

# 2) Cache expensive transforms with explicit keys
# compute_items() depends only on raw_df content. Hash the bytes so the cache is stable.
@st.cache_data(show_spinner=False, max_entries=3)
def _df_signature(df: pd.DataFrame) -> str:
    # robust-ish signature for cache key
    h = hashlib.sha1()
    h.update(str(df.shape).encode())
    h.update("|".join(df.columns.astype(str)).encode())
    h.update(pd.util.hash_pandas_object(df.head(50), index=False).values.tobytes())
    return h.hexdigest()
def load_table(upload) -> pd.DataFrame:
    if upload is None: return pd.DataFrame()
    name = upload.name.lower()
    try:
        if name.endswith(".csv"):
            df = pd.read_csv(upload, encoding="latin1", engine="python", skiprows=2)
        elif name.endswith((".xlsx", ".xls")):
            df = pd.read_excel(upload, skiprows=2, engine="openpyxl")
        else:
            st.error("Please upload a .csv or .xlsx file."); return pd.DataFrame()
        return df
    except Exception as e:
        st.error(f"Error loading file: {e}")
        return pd.DataFrame()

# ---------------------- Transform (robust) ----------------------
# 6) Vectorize types early (smaller & faster)
# Cut memory + speed up groupbys.
def _shrink(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    num_cols = ["Initial_Qty","Remeasure_Add","Revised_Qty","Used_Qty","Remaining_Qty"]
    for c in num_cols:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce").astype("float32")
    cat_cols = ["Project_Key","Subcontractor_Key","WO_Key","OD_UOM","OD_Stage"]
    for c in cat_cols:
        if c in df.columns:
            df[c] = df[c].astype("category")
            return df



@st.cache_data
def compute_items(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty: return df
    df = rename_with_prefix(df)

    col_ref  = best_col(df, "OI_Ref. #") or "OI_Ref. #"
    col_proj = best_col(df, "OI_Project") or "OI_Project"
    col_subc = best_col(df, "OI_Subcontractor Name") or "OI_Subcontractor Name"
    col_date = best_col(df, "OI_Date") or "OI_Date"
    col_lt   = best_col(df, "OD_Line Type") or "OD_Line Type"
    col_ln   = best_col(df, "OD_Line #") or "OD_Line #"

    for need in [col_ref, col_proj, col_subc, col_lt, col_ln, col_date]:
        if need not in df.columns: df[need] = np.nan

    lt_series = df[col_lt].astype(str).str.strip().str.lower()
    items = df.copy()  # default (some exports omit clear 'Item' tagging)
    mask_item = (
        lt_series.eq("item")
    |   lt_series.str.contains(r"\bitem\b", na=False)
    |   lt_series.str.contains(r"boq", na=False)
)
    if mask_item.any():
        items = df[mask_item].copy()

    # robust, alias-aware resolution
    src_initial = find_qty_source(items, "OD_Qty.")
    src_rmc     = find_qty_source(items, "RMC_Qty..1")
    src_rv      = find_qty_source(items, "RV_Qty..2")
    src_used    = find_qty_source(items, "CERT_Cert. Qty..1")
    src_rmn     = find_qty_source(items, "RMN_Cert. Qty..2")


    for c in [src_initial, src_rmc, src_rv, src_used, src_rmn]:
        if c not in items.columns: items[c] = np.nan

    items["Initial_Qty"]   = coerce_number(items[src_initial]).fillna(0.0)
    items["Remeasure_Add"] = coerce_number(items[src_rmc]).fillna(0.0)
    rv_tmp                 = coerce_number(items[src_rv])
    items["Revised_Qty"]   = np.where(rv_tmp.notna(), rv_tmp, items["Initial_Qty"] + items["Remeasure_Add"])
    items["Used_Qty"]      = coerce_number(items[src_used]).fillna(0.0)
    rmn_tmp                = coerce_number(items[src_rmn])
    items["Remaining_Qty"] = np.where(rmn_tmp.notna(), rmn_tmp, np.maximum(items["Revised_Qty"] - items["Used_Qty"], 0.0))

    if col_date in items.columns: items[col_date] = coerce_date(items[col_date])
    if best_col(items, "II_Date.1"):
        col_iidate = best_col(items, "II_Date.1")
        items[col_iidate] = coerce_date(items[col_iidate])

    for c in [
        "OD_Description","OD_UOM","OD_Rate","OD_Amount","OD_Remarks","OD_BOQ Item","OD_Internal Item","OD_Rate Only",
        "OD_Cost Code","OD_Cost Code Description","OD_Cost Head Code","OD_Cost Head Description",
        "OD_Prime Activity Code","OD_Prime Activity Name","OD_Phase","OD_Block","OD_Plot","OD_VAT Type","OD_VAT Code","OD_Stage",
        "OI_Title","II_Title.1","II_Nature Name","II_Approval Status","II_Instruction Status","II_Finalisation Status.1","II_Claim Amount"
    ]:
        if best_col(items, c) and best_col(items, c) != c:
            items[c] = items[best_col(items, c)]
        if c not in items.columns: items[c] = np.nan

    items["WO_Key"]           = items[col_ref].astype(str).str.strip()
    items["Project_Key"]      = items[col_proj].astype(str).str.strip()
    items["Subcontractor_Key"]= items[col_subc].astype(str).str.strip()
    items["Line_Key"]         = items[col_ln].astype(str).str.strip()
    if items["Line_Key"].isna().all() or (items["Line_Key"].astype(str).str.strip()=="").all():
        items["Line_Key"] = items.groupby(["Project_Key","WO_Key"]).cumcount()+1
        items["Line_Key"] = items["Line_Key"].astype(str)

    items.__dict__["_lt_filter_note"] = (
        "eq('Item')" if (lt_series.eq("item").any())
        else ("contains('item')" if (lt_series.str.contains("item", na=False).any()) else "no-filter (fallback)")
    )
    return items

@st.cache_data
def wo_summary(items: pd.DataFrame) -> pd.DataFrame:
    if items.empty: return items
    return items.groupby(["WO_Key","Project_Key","Subcontractor_Key"], dropna=False).agg(
        Lines=("Line_Key","nunique"),
        Initial_Qty=("Initial_Qty","sum"),
        Remeasure_Add=("Remeasure_Add","sum"),
        Revised_Qty=("Revised_Qty","sum"),
        Used_Qty=("Used_Qty","sum"),
        Remaining_Qty=("Remaining_Qty","sum"),
    ).reset_index()

# 4) Avoid re-grouping massive DataFrames for every expander
# Precompute once per filter and reuse.
@st.cache_data(show_spinner=False, max_entries=10)
def pre_aggregations(df: pd.DataFrame):
    if df.empty:
        return pd.DataFrame(), pd.DataFrame(), pd.DataFrame()
    wo = wo_summary(df)
    proj = wo.groupby("Project_Key", dropna=False)[["Initial_Qty","Remeasure_Add","Revised_Qty","Used_Qty","Remaining_Qty"]].sum().reset_index()
    sub  = wo.groupby("Subcontractor_Key", dropna=False)[["Initial_Qty","Remeasure_Add","Revised_Qty","Used_Qty","Remaining_Qty"]].sum().reset_index()
    return wo, proj, sub

# ---------------------- PDF helpers ----------------------
@st.cache_resource
def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="BrandTitle", fontName="Helvetica-Bold", fontSize=14, textColor=colors.HexColor(BRAND_BLACK), spaceAfter=6))
    styles.add(ParagraphStyle(name="BrandH2", fontName="Helvetica-Bold", fontSize=12, textColor=colors.HexColor(BRAND_BLUE), spaceAfter=4))
    styles.add(ParagraphStyle(name="Small", fontName="Helvetica", fontSize=8, textColor=colors.black, leading=10))
    styles.add(ParagraphStyle(name="Mini", fontName="Helvetica", fontSize=7, textColor=colors.black, leading=9))
    styles.add(ParagraphStyle(name="Cell", fontName="Helvetica", fontSize=8, leading=10, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="CellBold", parent=styles["Cell"], fontName="Helvetica-Bold"))
        # === Emphasis styles for Reference & Integrity ===
    styles.add(ParagraphStyle(
        name="MetaLabel",
        parent=styles["Small"],
        fontName="Helvetica-Bold",
        fontSize=12,
        textColor=colors.HexColor(BRAND_BLACK),
        leading=14,
        spaceAfter=0,
    ))
    styles.add(ParagraphStyle(
        name="MetaValue",
        parent=styles["Small"],
        fontName="Helvetica-Bold",
        fontSize=12,               # bigger value text
        textColor=colors.HexColor(BRAND_BLACK),
        leading=15,
        spaceAfter=0,
    ))
    styles.add(ParagraphStyle(
        name="MetaValueMono",
        parent=styles["Small"],
        fontName="Courier",        # monospace for integrity hash
        fontSize=12,
        textColor=colors.HexColor(BRAND_BLACK),
        leading=14,
        spaceAfter=0,
    ))
    # --- Robust description resolver + cleaner ---
    DESC_ALIASES = [
        "OD_Description", "Description", "Item Description", "BOQ Item",
        "OD_BOQ Item", "Work Item Description", "Scope", "Item", "Narration",
        "II_Title.1", "OI_Title"
    ]
    
    return styles

def _table_style():
    return TableStyle([
        ("FONT", (0,0), (-1,0), "Helvetica-Bold", 9),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor(BRAND_BLUE)),
        ("FONT", (0,1), (-1,-1), "Helvetica", 8),
        ("GRID", (0,0), (-1,-1), 0.25, colors.HexColor(BRAND_GREY)),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.whitesmoke, colors.HexColor("#F7F9FB")]),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING", (0,0), (-1,-1), 4),
        ("RIGHTPADDING", (0,0), (-1,-1), 4),
        ("TOPPADDING", (0,0), (-1,-1), 3),
        ("BOTTOMPADDING", (0,0), (-1,-1), 3),
    ])

# ===== Integrated Engine (idempotency + auto-approvals + immutable reprint) =====
ENGINE_VERSION = "v2.9.0"

REQUIRED_REG_COLS = [
    "ref","hash","project_code","project_name","request_type","vendor","wo",
    "line_key","uom","stage","description","qty","date_casting","date_testing",
    "remarks","remaining_at_request","approval_required","approval_reason",
    "is_new_item","generated_at","generated_by_name","generated_by_email",
    "status","approver","approved_at",
    # Engine extras
    "idem_key","status_detail","auto_approved_at","auto_approved_by",
    "engine_version","snap_company_name","snap_address_1","snap_address_2", "line_item" # Added line_item
]

def ensure_registry_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    for c in REQUIRED_REG_COLS:
        if c not in df.columns:
            df[c] = ""
    return df

def _coerce_float(v) -> float:
    try:
        if v is None or (isinstance(v, float) and np.isnan(v)):
            return float("nan")
        return float(v)
    except (ValueError, TypeError):
        return float("nan")

def compute_idempotency_key(entry: Dict, user_email: str) -> str:
    parts = [
        entry.get("project_code",""), entry.get("request_type",""),
        entry.get("vendor",""), entry.get("wo",""), entry.get("line_key",""),
        entry.get("uom",""), entry.get("stage",""), str(entry.get("description","")).strip(),
        str(entry.get("qty","")), str(entry.get("date_casting","")), str(entry.get("date_testing","")),
        str(entry.get("remarks","")).strip(), user_email or ""
    ]
    raw = "|".join(str(x) for x in parts)
    return _sha256_hex(raw)[:24].upper()

def next_counter_for(project_code: str, request_type: str, reqlog_df: pd.DataFrame) -> int:
    if reqlog_df.empty: return 1
    sub = reqlog_df[(reqlog_df["project_code"]==project_code) & (reqlog_df["request_type"]==request_type)]
    if sub.empty: return 1
    ctrs = []
    for r in sub["ref"].astype(str):
        try:
            part = r.split("/")[-1].split("-")[0]
            ctrs.append(int(part))
        except (ValueError, IndexError):
            pass
    return max(ctrs) + 1 if ctrs else 1

def generate_ref(project_code: str, request_type: str, counter: int) -> str:
    uid_suffix = uuid.uuid4().hex[:4].upper()
    return f"SJCPL/{project_code}/{request_type}/{counter:04d}-{uid_suffix}"

def requirement_hash(ref: str, created_at_iso: str, user_email: str, req_hash_salt: str) -> str:
    return _hmac_hex(f"{ref}|{created_at_iso}|{user_email}", req_hash_salt)[:16].upper()

def _current_remaining(items_df: pd.DataFrame, entry: Dict) -> float:
    try:
        if entry.get("line_key","") == "NEW":
            return float("nan")
        mask = (
            (items_df.get("Project_Key","") == entry["project_code"]) &
            (items_df.get("Subcontractor_Key","") == entry["vendor"]) &
            (items_df.get("WO_Key","") == entry["wo"]) &
            (items_df.get("Line_Key","").astype(str) == str(entry["line_key"]))
        )
        rem = pd.to_numeric(items_df.loc[mask, "Remaining_Qty"], errors="coerce")
        if rem.empty:
            return float("nan")
        return float(rem.iloc[0])
    except Exception:
        return float("nan")

def _decide_status(entry: Dict, items_df: pd.DataFrame) -> Tuple[str, str, Optional[str]]:
    qty = _coerce_float(entry.get("qty", 0))
    is_new = bool(entry.get("is_new_item", False))
    
    if is_new:
        return ("Pending Admin Approval", "Awaiting new item creation in CSV; admin must approve first.", None)

    rem = _current_remaining(items_df, entry)
    if np.isnan(rem):
        return ("Pending Admin Approval", "Line not found in current CSV; admin must approve.", None)

    if qty <= 0:
        return ("Rejected", "Quantity must be > 0", None)

    if rem > 0 and qty <= rem:
        return ("Auto Approved", "In-stock quantity available at request time.", "System")
    else:
        return ("Pending Admin Approval", "Quantity addition requested; admin must approve.", None)

def _can_send_vendor_email(status: str) -> bool:
    s = (status or "").strip()
    return s in ("Approved", "Auto Approved")

def email_vendors_if_autoapproved(
    rows_from_generation: list[dict],
    pdf_bytes: bytes,
    requester_name: str,
    requester_email: str,
    send_if_checked: bool
) -> None:
    """Send vendor emails for rows that are Auto Approved and not already emailed."""
    if not send_if_checked or not rows_from_generation or not pdf_bytes:
        return

    # Imports here so any adapter errors show to the user
    from db_adapter import ( # This block is duplicated
        read_requirements_by_refs,
        get_vendor_email,
        log_requirement_email,
        mark_vendor_emailed,
    )

    refs = [r.get("ref") for r in rows_from_generation if r.get("ref")]
    if not refs:
        return

    # Re-read the latest rows from DB to know the current status and emailed flags
    latest = read_requirements_by_refs(refs)
    by_ref = {r.get("ref"): r for r in latest}

    sent_refs = []
    sent_count = 0

    for r in rows_from_generation:
        ref = r.get("ref")
        if not ref:
            continue
        lr = by_ref.get(ref, r)  # latest row if available
        status = str(lr.get("status", ""))

        # Skip if not Auto Approved
        if status != "Auto Approved":
            continue

        # Skip if already emailed to vendor
        if lr.get("emailed_vendor_at") or lr.get("vendor_emailed_at"):
            continue

        v_email = get_vendor_email(lr.get("vendor", ""))
        if not v_email:
            # No vendor email saved — skip silently (or show a toast elsewhere)
            continue

        # Subject + HTML EXACTLY as you requested
        subject = f"SJCPL — Test Request: {ref}"
        html = build_vendor_email_html(lr)
        attach_name = f"{ref}.pdf"

        ok, msg = send_email_via_smtp(to_email=v_email, subject=subject, html_body=html, attachment_bytes=pdf_bytes, attachment_name=attach_name)

        log_requirement_email(ref=ref, vendor=lr.get("vendor", ""), email=v_email, subject=subject, ok=ok, error=None if ok else (msg or "send failed"))

        if ok:
            sent_refs.append(ref)
            sent_count += 1

    if sent_refs:
        try:
            mark_vendor_emailed(sent_refs, requester_email)
        except Exception:
            pass
        st.success(f"Vendor emailed for {sent_count} auto-approved request(s).")

def build_requirement_pdf_from_rows(rows: List[Dict], company_meta: Dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=18*mm, rightMargin=18*mm, topMargin=18*mm, bottomMargin=18*mm)
    styles = _styles()

    # --- Ensure emphasis styles exist (safe if already present) ---
    try:
        _ = styles["MetaLabel"]; _ = styles["MetaValue"]; _ = styles["MetaValueMono"]
    except KeyError:
        styles.add(ParagraphStyle(
            name="MetaLabel", parent=styles["Small"], fontName="Helvetica-Bold",
            fontSize=12, textColor=colors.HexColor(BRAND_BLUE), leading=14, spaceAfter=0
        ))
        styles.add(ParagraphStyle(
            name="MetaValue", parent=styles["Small"], fontName="Helvetica-Bold",
            fontSize=13, textColor=colors.HexColor(BRAND_BLACK), leading=15, spaceAfter=0
        ))
        styles.add(ParagraphStyle(
            name="MetaValueMono", parent=styles["Small"], fontName="Courier",
            fontSize=12, textColor=colors.HexColor(BRAND_BLACK), leading=14, spaceAfter=0
        ))

    # --- Safe converters for Paragraph/text ---
    def _is_nanlike(v) -> bool:
        try:
            return v is None or (isinstance(v, float) and np.isnan(v)) or (isinstance(v, str) and v.strip().lower() in {"nan", "none"})
        except Exception:
            return False

    def _esc(s: str) -> str:
        # minimal HTML escaping for reportlab paragraphs
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def _to_text(v, dash="—") -> str:
        if _is_nanlike(v):
            return dash
        try:
            s = str(v)
        except Exception:
            s = dash
        # Normalize NBSP and trim
        s = s.replace("\u00a0", " ").strip()
        return s if s else dash

    def _to_para(v, style) -> Paragraph:
        return Paragraph(_esc(_to_text(v)), style)

    story = []
    avail_w = landscape(A4)[0] - 18*mm - 18*mm

    for i, p in enumerate(rows, start=1):
        comp_name = _to_text(p.get("snap_company_name")) if p.get("snap_company_name") else _to_text(company_meta.get("name", "SJCPL"))
        addr1 = _to_text(p.get("snap_address_1")) if p.get("snap_address_1") else _to_text((company_meta.get("address_lines") or ["",""])[0])
        addr2 = _to_text(p.get("snap_address_2")) if p.get("snap_address_2") else _to_text((company_meta.get("address_lines") or ["",""])[1])

        logo_flowable = None
        if st.session_state.get("company_logo"):
            try:
                st.session_state.company_logo.seek(0)
                logo_flowable = RLImage(st.session_state.company_logo, width=40*mm, height=15*mm, hAlign="LEFT")
            except Exception:
                logo_flowable = None

        header_left = logo_flowable or Paragraph(f"<b>{_esc(comp_name)}</b>", styles["BrandH2"])
        small_right = ParagraphStyle("SmallRight", parent=styles["Small"], alignment=TA_RIGHT)
        header_right = Paragraph(f"{_esc(comp_name)}<br/>{_esc(addr1)}<br/>{_esc(addr2)}", small_right)

        header_table = Table([[header_left, header_right]], colWidths=[avail_w * 0.4, avail_w * 0.6])
        header_table.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('LINEBELOW', (0,0), (-1,-1), 1, colors.HexColor(BRAND_GREY)),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(header_table)
        story.append(Spacer(1, 4*mm))

        # -------- HIGHLIGHTED META (Reference + Integrity) --------
        ref_text = _to_text(p.get("ref"))
        gen_at   = _to_text(p.get("generated_at"))
        gen_by   = _to_text(p.get("generated_by_name"))
        integ    = _to_text(p.get("hash"))

        meta_table_data = [
            [Paragraph("Reference", styles["MetaLabel"]),
             Paragraph(_esc(ref_text), styles["MetaValue"])],
            [Paragraph("Integrity", styles["MetaLabel"]),
             Paragraph(_esc(integ), styles["MetaValueMono"])],
        ]
        meta_table = Table(meta_table_data, colWidths=[35*mm, avail_w - 35*mm], hAlign="LEFT")
        meta_table.setStyle(TableStyle([
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor(BRAND_BLUE)),
            ("BOX", (0,0), (-1,-1), 0.6, colors.HexColor(BRAND_GREY)),
            ("INNERGRID", (0,0), (-1,-1), 0.25, colors.HexColor("#D0D7DE")),
            ("LEFTPADDING", (0,0), (-1,-1), 6),
            ("RIGHTPADDING", (0,0), (-1,-1), 6),
            ("TOPPADDING", (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 2*mm))

        _dt_raw = _to_text(p.get("generated_at"))
        try:
            _dt_fmt = pd.to_datetime(_dt_raw)
            gen_at_fmt = _dt_fmt.strftime("%d %b %Y, %H:%M:%S")  # e.g., 25 Sep 2025, 12:53:14
        except Exception:
            gen_at_fmt = _dt_raw if _dt_raw != "—" else "—"

        dt_by_html = (
            f"<b>Date &amp; Time:</b> {_esc(gen_at_fmt)}"
            f"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
            f"<b>Generated by:</b> {_esc(gen_by)}"
        )
        story.append(Paragraph(dt_by_html, styles["Small"]))
        story.append(Spacer(1, 3*mm))

        # -------- Project/Vendor/WO/Type line --------
        proj_name = _to_text(p.get("project_name"))
        proj_code = _to_text(p.get("project_code"))
        vendor    = _to_text(p.get("vendor"))
        wo        = _to_text(p.get("wo"))
        rtype     = _to_text(p.get("request_type"))

        # Keep WO unbroken as much as possible: replace spaces with NBSP inside WO value
        wo_nbsp = _esc(wo.replace(" ", "\u00A0"))

        pvt_tbl = Table(
            [
                [
                Paragraph("<b>Project:</b>", styles["Small"]),
                Paragraph(f"{_esc(proj_name)} ({_esc(proj_code)})", styles["Small"]),
                Paragraph("<b>Vendor:</b>", styles["Small"]),
                Paragraph(_esc(vendor), styles["Small"])
            ],

                [
                Paragraph("<b>Work Order:</b>", styles["Small"]),
                Paragraph(wo_nbsp, styles["Small"]),
                Paragraph("<b>Type:</b>", styles["Small"]),
                Paragraph(_esc(rtype), styles["Small"])],
            ],
        # label, value, label, value
        colWidths=[22*mm, 0.45*avail_w, 18*mm, 0.45*avail_w],
        hAlign="LEFT",
        )
        pvt_tbl.setStyle(TableStyle([
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
            ("LEFTPADDING", (0,0), (-1,-1), 0),
            ("RIGHTPADDING", (0,0), (-1,-1), 6),
            ("TOPPADDING", (0,0), (-1,-1), 0),
            ("BOTTOMPADDING", (0,0), (-1,-1), 2),
        ]))
        story.append(pvt_tbl)
        story.append(Spacer(1, 4*mm))

        # -------- Item table --------
        headers = ["Sr.", "Date", "Item Description", "Qty", "UOM", "Date of Casting", "Date of Testing", "Remarks"]
        try:
            d = pd.to_datetime(p.get("generated_at")).strftime("%d-%m-%Y")
        except Exception:
            d = _to_text(p.get("generated_at")).split(" ")[0] if _to_text(p.get("generated_at")) != "—" else "—"
 # Prefer showing the human "Line Item" label, then free text below it:
        # Escape description and stage
        desc = _esc(_to_text(p.get("description")))
        stage = _esc(_to_text(p.get("stage"), dash="N/A"))
        item_desc_text = f"{desc} <br/> (Stage: {stage})"

        qty_val = _coerce_float(p.get("qty", ""))
        qty_str = f"{qty_val:.2f}" if not np.isnan(qty_val) else "—"
 # e.g., "Line 8.0 — Charges for AAC Block Test - Compressive Strength Test"
 # and on next line your edited Description (if different). # This line is duplicated
        line_item = p.get("line_item", "")
        if line_item and line_item.lower() != desc.lower():
            item_desc_text = f"<b>{line_item}</b><br/>{desc} <br/> (Stage: {stage})"
        else:
            item_desc_text = f"{desc} <br/> (Stage: {stage})"
        row_data = [
            "1",
            _esc(d),
            Paragraph(item_desc_text, styles["Cell"]),
            qty_str,
            _esc(_to_text(p.get("uom"))),
            _esc(_to_text(p.get("date_casting"))),
            _esc(_to_text(p.get("date_testing"))),
            Paragraph(_esc(_to_text(p.get("remarks"))), styles["Cell"])
        ]

        col_widths = [15*mm, 20*mm, 100*mm, 15*mm, 15*mm, 25*mm, 25*mm, 45*mm]

        t = Table([headers, row_data], colWidths=col_widths)
        tbl_style = _table_style()
        tbl_style.add("ALIGN", (3,1), (3,1), "RIGHT")
        t.setStyle(tbl_style)
        story.append(t)
        story.append(Spacer(1, 4*mm))

        # -------- Status --------
        status_text = f"<b>Status:</b> {_esc(_to_text(p.get('status')))} &nbsp;&nbsp; <b>Detail:</b> {_esc(_to_text(p.get('status_detail')))}"
        story.append(Paragraph(status_text, styles["Small"]))

        if i < len(rows):
            story.append(PageBreak())

    doc.build(story)
    return buf.getvalue()


def generate_pdf_and_log_lines(
    cart_entries: List[Dict],
    user: Dict,
    reqlog_df: pd.DataFrame,
    items_df: pd.DataFrame,
    company_meta: Dict,
    req_hash_salt: str
) -> Tuple[bytes, pd.DataFrame, Dict[str, str], List[Dict]]:
    if not isinstance(reqlog_df, pd.DataFrame):
        reqlog_df = pd.DataFrame(columns=REQUIRED_REG_COLS)
    reqlog_df = ensure_registry_columns(reqlog_df)

    now_iso = dt.datetime.now(pytz.timezone("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S")
    created_by = user.get("name", "User")
    email = user.get("email", "user@sjcpl.local")

    ctr_cache: Dict[Tuple[str, str], int] = {}
    pages_rows: List[Dict] = []
    reused_map: Dict[str, str] = {}

    for entry in cart_entries:
        # --- NORMALIZE DESCRIPTION at save time (bulletproof) --- # This block is duplicated
        line_key_str = str(entry.get("line_key","")).strip()
        if line_key_str and line_key_str.upper() != "NEW":
            sel = items_df[
                (items_df["Project_Key"].astype(str)==str(entry.get("project_code",""))) &
                (items_df["Subcontractor_Key"].astype(str)==str(entry.get("vendor",""))) &
                (items_df["WO_Key"].astype(str)==str(entry.get("wo",""))) &
                (items_df["Line_Key"].astype(str)==line_key_str)
            ].head(1)
            if not sel.empty:
                dcol = resolve_desc_col(sel) or resolve_desc_col(items_df) or "OD_Description"
                raw_desc = str(sel.iloc[0].get(dcol, "")).strip()
                cleaned = _clean_line_caption(f"Line {line_key_str} — {raw_desc}")
                entry["description"] = cleaned
                entry["line_item"] = cleaned # Keep line_item in sync with description
        else:
            entry["description"] = _clean_line_caption(str(entry.get("description","")))
            entry["line_item"] = entry["description"]

        # Check if description is valid after normalization
        desc_ok = bool(str(entry.get("description","")).strip())
        qty = _coerce_float(entry.get("qty", 0))
        if not desc_ok or qty <= 0:
            continue

    for entry in cart_entries: # Re-iterate after normalization # This block is duplicated
        desc_ok = bool(str(entry.get("description","")).strip())
        qty = _coerce_float(entry.get("qty", 0))
        if not desc_ok or qty <= 0:
            continue

        idem = compute_idempotency_key(entry, email)
        dup = reqlog_df[reqlog_df["idem_key"] == idem]
        
        if not dup.empty:
            row = dup.iloc[0].to_dict()
            reused_map[idem] = row["ref"]
            pages_rows.append(row)
            continue

        key = (entry["project_code"], entry["request_type"])
        if key not in ctr_cache:
            ctr_cache[key] = next_counter_for(entry["project_code"], entry["request_type"], reqlog_df)
        
        ref = generate_ref(entry["project_code"], entry["request_type"], ctr_cache[key]); ctr_cache[key] += 1
        hsh = requirement_hash(ref, now_iso, email, req_hash_salt)
        status, status_detail, auto_by = _decide_status(entry, items_df)

        row = {
            "ref": ref, "hash": hsh,
            "project_code": entry["project_code"], "project_name": entry.get("project_name", entry["project_code"]),
            "request_type": entry["request_type"], "vendor": entry["vendor"], "wo": entry["wo"],
            "line_key": entry["line_key"], "uom": entry["uom"], "stage": entry["stage"],
            "description": entry["description"].strip(), "qty": float(qty),
            "date_casting": entry.get("date_casting",""), "date_testing": entry.get("date_testing",""),
            "remarks": entry.get("remarks",""),
            "remaining_at_request": entry.get("remaining_at_request",""),
            "approval_required": entry.get("approval_required", False),
            "approval_reason": entry.get("approval_reason",""),
            "line_item": entry.get("line_item",""),
            "is_new_item": bool(entry.get("is_new_item", False)),
            "generated_at": now_iso, "generated_by_name": created_by, "generated_by_email": email,
            "status": status, "approver": (auto_by or ""), "approved_at": (now_iso if auto_by else ""),
            "idem_key": idem, "status_detail": status_detail, "auto_approved_at": (now_iso if auto_by else ""),
            "auto_approved_by": (auto_by or ""), "engine_version": ENGINE_VERSION,
            "snap_company_name": company_meta.get("name","SJCPL"),
            "snap_address_1": (company_meta.get("address_lines") or ["",""])[0],
            "snap_address_2": (company_meta.get("address_lines") or ["",""])[1],
        }
        reqlog_df.loc[len(reqlog_df)] = row
        pages_rows.append(row)

    pdf_bytes = build_requirement_pdf_from_rows(pages_rows, company_meta) if pages_rows else b""
    return pdf_bytes, reqlog_df, reused_map, pages_rows

def run_post_csv_auto_approvals(reqlog_df: pd.DataFrame, items_df: pd.DataFrame) -> Tuple[pd.DataFrame, int]:
    if reqlog_df.empty:
        return reqlog_df, 0
    df = ensure_registry_columns(reqlog_df).copy()
    changed = 0
    now_iso = dt.datetime.now(pytz.timezone("Asia/Kolkata")).strftime("%Y-%m-%d %H:%M:%S")

    items = items_df.copy() if isinstance(items_df, pd.DataFrame) else pd.DataFrame()
    items["Line_Key"] = items.get("Line_Key","").astype(str)

    for idx, r in df.iterrows():
        stt = str(r.get("status",""))
        reason = str(r.get("approval_reason",""))
        if reason not in {"low_qty","new_item"}:
            continue
        if stt not in {"Approved", "Pending Admin Approval"}:
            continue

        qty = _coerce_float(r.get("qty"))
        proj = r.get("project_code",""); vendor = r.get("vendor",""); wo = r.get("wo","")
        line_key = str(r.get("line_key",""))
        desc = str(r.get("description","")).strip()
        uom = str(r.get("uom","")).strip()

        auto_ok = False
        if reason == "low_qty":
            mask = (
                (items.get("Project_Key","") == proj) &
                (items.get("Subcontractor_Key","") == vendor) &
                (items.get("WO_Key","") == wo) &
                (items.get("Line_Key","").astype(str) == line_key)
            )
            rem = pd.to_numeric(items.loc[mask, "Remaining_Qty"], errors="coerce")
            if not rem.empty and rem.iloc[0] >= qty and qty > 0:
                auto_ok = True
        else:
            mask = (
                (items.get("Project_Key","") == proj) &
                (items.get("Subcontractor_Key","") == vendor) &
                (items.get("WO_Key","") == wo) &
                (items.get("OD_UOM","").astype(str).str.strip() == uom)
            )
            cand = items.loc[mask].copy()
            if not cand.empty:
                pat = desc.lower()[:20]
                if pat:
                    cand = cand[cand.get("OD_Description","").astype(str).str.lower().str.contains(pat, na=False)]
                rem = pd.to_numeric(cand.get("Remaining_Qty", pd.Series(dtype=float)), errors="coerce")
                if not rem.empty and (rem > 0).any():
                    auto_ok = True

        if auto_ok:
            df.at[idx, "status"] = "Auto Approved"
            df.at[idx, "status_detail"] = "Stock available post CSV update (after admin approval)."
            df.at[idx, "auto_approved_by"] = "System"
            df.at[idx, "auto_approved_at"] = now_iso
            changed += 1

    return df, changed

# CHANGE SIGNATURE: add key_prefix with a default to avoid breaking other calls
def render_reprint_section(st, reqlog_df: pd.DataFrame, company_meta: Dict, key_prefix: str = "reprint"):
    # Guard: empty / missing frame
    if not isinstance(reqlog_df, pd.DataFrame) or reqlog_df.empty:
        st.caption("Registry is empty.")
        return

    df_filtered = reqlog_df # (no boolean checks on a DataFrame) # This line is duplicated

    refs = st.multiselect(
        "Select Reference(s) to reprint",
        df_filtered["ref"].astype(str).tolist(),
        default=[],
        key=f"{key_prefix}-refs"
    )

    if refs and st.button("🖨️ Build PDF for selected", type="primary", key=f"{key_prefix}-build"):
        rows = df_filtered[df_filtered["ref"].isin(refs)].sort_values("generated_at").to_dict(orient="records")
        pdf_bytes = build_requirement_pdf_from_rows(rows, company_meta)
        st.download_button(
            "Download PDF (selected refs)",
            data=pdf_bytes,
            file_name="requirements_reprint.pdf",
            mime="application/pdf",
            key=f"{key_prefix}-dl",
        )

def render_my_requests_tab(st, user_email: str, reqlog_df: pd.DataFrame, company_meta: Dict):
    st.subheader("My Requests & Logs") # This function is duplicated

    df = ensure_registry_columns(reqlog_df).copy()
    mine = df[df["generated_by_email"] == user_email].copy()

    if mine.empty:
        st.info("You haven't generated any requests yet.")
        return
    
        # ---------- Quick summary tiles ---------- # Removed vendor email checkbox from here
        st.session_state["selected_refs_for_vendor_send"] = []
    total = len(mine)
    n_pend = int((mine["status"].astype(str).str.startswith("Pending")).sum())
    n_appr = int((mine["status"] == "Approved").sum())
    n_auto = int((mine["status"] == "Auto Approved").sum())
    n_rej  = int((mine["status"] == "Rejected").sum())

    cA, cB, cC, cD, cE = st.columns(5)
    cA.metric("Total requests", total)
    cB.metric("Pending", n_pend)
    cC.metric("Approved", n_appr)
    cD.metric("Auto Approved", n_auto)
    cE.metric("Rejected", n_rej)

    # ---------- Filters ----------
    f1, f2, f3 = st.columns(3)
    with f1:
        status_pick = st.multiselect("Status", sorted(mine["status"].dropna().unique()), default=[])
    with f2:
        proj_pick = st.multiselect("Project", sorted(mine["project_code"].dropna().unique()), default=[])
    with f3:
        vendor_pick = st.multiselect("Vendor", sorted(mine["vendor"].dropna().unique()), default=[])

    view = mine.copy()
    if status_pick:
        view = view[view["status"].isin(status_pick)]
    if proj_pick:
        view = view[view["project_code"].isin(proj_pick)]
    if vendor_pick:
        view = view[view["vendor"].isin(vendor_pick)]

    # ---------- Request Log (tabular) ----------
    st.markdown("### Request Log")
    log_cols = [
        "generated_at","ref","project_code","vendor","request_type",
        "description","qty","uom","status","approver","approved_at"
    ]
    # Safe subset + ordering
    show = [c for c in log_cols if c in view.columns]
    log = view[show].copy().sort_values("generated_at", ascending=False)

    # Pretty status chips (simple HTML)
    def _chip(s: str) -> str:
        s = str(s or "")
        if s == "Approved":
            bg = "#e6ffed"; fg = "#067d2e"
        elif s == "Auto Approved":
            bg = "#e6f4ff"; fg = "#0b5394"
        elif s.startswith("Pending"):
            bg = "#fff4e5"; fg = "#9a6700"
        elif s == "Rejected":
            bg = "#ffe6e6"; fg = "#a40000"
        else:
            bg = "#f2f2f2"; fg = "#444"
        return f"<span style='display:inline-block;padding:2px 8px;border-radius:999px;background:{bg};color:{fg};font-weight:600;font-size:12px'>{s}</span>"

    # Render a compact HTML table for a cleaner status look (while keeping a CSV below)
    html_rows = []
    for _, r in log.iterrows():
        html_rows.append(
            f"<tr>"
            f"<td style='padding:6px 8px;white-space:nowrap'>{r.get('generated_at','')}</td>"
            f"<td style='padding:6px 8px'>{r.get('ref','')}</td>"
            f"<td style='padding:6px 8px'>{r.get('project_code','')}</td>"
            f"<td style='padding:6px 8px'>{r.get('vendor','')}</td>"
            f"<td style='padding:6px 8px'>{r.get('request_type','')}</td>"
            f"<td style='padding:6px 8px'>{(str(r.get('description',''))[:80] + ('…' if len(str(r.get('description',''))) > 80 else ''))}</td>"
            f"<td style='padding:6px 8px; text-align:right'>{r.get('qty','')} {r.get('uom','')}</td>"
            f"<td style='padding:6px 8px'>{_chip(r.get('status'))}</td>"
            f"<td style='padding:6px 8px'>{r.get('approver','')}</td>"
            f"<td style='padding:6px 8px;white-space:nowrap'>{r.get('approved_at','')}</td>"
            f"</tr>"
        )
    log_html = f"""
    <div style="overflow:auto">
      <table style="border-collapse:collapse;font-size:13px;min-width:900px">
        <thead>
          <tr style="background:#f6f8fa">
            <th style="padding:6px 8px;text-align:left;white-space:nowrap">Generated</th>
            <th style="padding:6px 8px;text-align:left">Ref</th>
            <th style="padding:6px 8px;text-align:left">Project</th>
            <th style="padding:6px 8px;text-align:left">Vendor</th>
            <th style="padding:6px 8px;text-align:left">Type</th>
            <th style="padding:6px 8px;text-align:left">Item</th>
            <th style="padding:6px 8px;text-align:right">Qty</th>
            <th style="padding:6px 8px;text-align:left">Status</th>
            <th style="padding:6px 8px;text-align:left">Approver</th>
            <th style="padding:6px 8px;text-align:left;white-space:nowrap">Approved At</th>
          </tr>
        </thead>
        <tbody>
          {''.join(html_rows) if html_rows else "<tr><td colspan='10' style='padding:8px;color:#666'>No rows</td></tr>"}
        </tbody>
      </table>
    </div>
    """
    st.markdown(log_html, unsafe_allow_html=True)

    # Export current view
    st.download_button(
        "⬇️ Download my request log (CSV)",
        data=view[show].to_csv(index=False).encode("utf-8"),
        file_name="my_requests_log.csv",
        mime="text/csv",
        key="myreq-log-dl"
    )

    # ---------- Send Email to Vendor (Approved only) ----------
    st.markdown("---")
    with st.expander("📧 Send Email to Vendor (Approved / Auto Approved only)", expanded=True):
        sendable_refs = view[view["status"].isin(["Approved","Auto Approved"])]["ref"].astype(str).tolist()
        st.session_state["selected_refs_for_vendor_send"] = sendable_refs
        if not sendable_refs:
            st.caption("No Approved / Auto Approved requests in the current list.")
        else:
            sel_refs = st.multiselect("Select Approved reference(s) to email", sendable_refs, default=[], key="myreq-email-refs")
            if st.button("Send Email to Vendor (same as auto-approval)", type="primary", key="myreq-email-btn"):
                _send_vendor_emails_for_refs(sel_refs)

    # ---------- Reprint controls (unchanged) ----------
    render_reprint_section(st, mine, company_meta, key_prefix="myreq-reprint")

def send_vendor_emails_same_as_auto(refs: list[str]):
    """
    Manual Send-to-Vendor that mirrors auto-approval emails:
    - One email per reference (row)
    - Same subject & HTML body
    - Same single-reference PDF attachment
    """
    if not refs:
        st.warning("Select at least one reference.")
        return

    try:
        from db_adapter import read_requirements_by_refs, get_vendor_email, log_requirement_email, mark_vendor_emailed # This block is duplicated
    except Exception as e:
        st.error(f"DB adapter not ready: {e}")
        return

    rows = read_requirements_by_refs(refs) or []
    rows = [r for r in rows if str(r.get("status")) in ("Approved", "Auto Approved")]
    if not rows:
        st.info("Selected references are not Approved / Auto Approved yet. Vendor email is disabled.")
        return

    user = st.session_state.get("user", {})
    requester_name  = user.get("name", "User")
    requester_email = user.get("email", "user@sjcpl.local")
    
    company_meta    = st.session_state.get("company_meta", {})

    emailed_refs: list[str] = []

    for r in rows:
        vendor_key = str(r.get("vendor", "")).strip()
        v_email = None
        try:
            v_email = get_vendor_email(vendor_key)
        except Exception:
            pass

        if not v_email:
            st.warning(f"No vendor email configured for: {vendor_key or '(blank)'} — skipping {r.get('ref','')}.")

            # Optionally log the attempt
            try: log_requirement_email(r.get("ref"), vendor_key, "(missing)", "(n/a)", False, "vendor email missing")
            except Exception: pass
            continue

        # === SAME subject/body as auto-approval ===
        subject, html_body = build_autoapproved_vendor_subject_and_body(r, requester_name)

        # === SAME single-ref PDF as auto-approval ===
        pdf_bytes = build_requirement_pdf_from_rows([r], company_meta)
        attach    = f"{(r.get('ref') or 'Requirement').replace('/','_')}.pdf"

        ok, msg = send_email_via_smtp(v_email, subject, html_body, pdf_bytes, attach)
        if ok:
            emailed_refs.append(r.get("ref"))
            st.success(f"Sent {r.get('ref')} to {vendor_key} <{v_email}>")

            try: log_requirement_email(r.get("ref"), vendor_key, v_email, subject, True, "")
            except Exception: pass
        else:
            st.error(f"Failed to send {r.get('ref')} to {vendor_key} <{v_email}>: {msg or 'send failed'}")
            try: log_requirement_email(r.get("ref"), vendor_key, v_email, subject, False, msg or "send failed")
            except Exception: pass

def _send_vendor_emails_for_refs(refs: list[str]):
    if not refs:
        st.warning("Pick at least one reference.")
        return

    # Load rows and ensure all are sendable
    try: # This block is duplicated
        rows = read_requirements_by_refs(refs)
    except Exception as e:
        st.error(f"Could not load selected refs: {e}")
        return

    not_sendable = [r["ref"] for r in rows if not _can_send_vendor_email(str(r.get("status","")))]
    if not_sendable:
        st.error("Vendor emailing is allowed only for Approved / Auto Approved items. These are not allowed: " + ", ".join(not_sendable))
        return

    # Build one combined PDF for the selected refs
    try: # This block is duplicated
        pdf_bytes = build_requirement_pdf_from_rows(rows, st.session_state.company_meta)
    except Exception as e:
        st.error(f"PDF build failed: {e}")
        return

    # Send one email per vendor (group)
    from collections import defaultdict
    by_vendor = defaultdict(list) # This block is duplicated
    for r in rows:
        by_vendor[str(r.get("vendor",""))].append(r)

    sent_ok, sent_err = 0, []
    for vendor_key, bucket in by_vendor.items():
        v_email = None
        try:
            v_email = get_vendor_email(vendor_key)
            if not v_email:
                st.warning(f"No vendor email configured for: {vendor_key}. (Admin → Vendor Contacts)")
                continue

            subject = build_vendor_email_subject(bucket[0])
            body_rows = "".join(
                f"<tr><td style='padding:4px 8px'>{r.get('ref','')}</td>"
                f"<td style='padding:4px 8px'>{r.get('description','')}</td>"
                f"<td style='padding:4px 8px'>{r.get('qty','')} {r.get('uom','')}</td></tr>"
                for r in bucket
            )
            html_body = f"""
            <div style="font-family:Arial,Helvetica,sans-serif;color:#222">
              <p>The following request(s) have been <b>Approved</b>:</p>
              <table style="border-collapse:collapse;font-size:13px">
                <thead><tr style="background:#f0f0f0">
                  <th style="padding:4px 8px;text-align:left">Ref</th>
                  <th style="padding:4px 8px;text-align:left">Item</th>
                  <th style="padding:4px 8px;text-align:left">Qty</th>
                </tr></thead>
                <tbody>{body_rows}</tbody>
              </table>
              <p>Attached: approved request PDF.</p>
            </div>
            """
            attach_name = f"Approved_{bucket[0].get('project_code','')}.pdf"

            ok_mail, msg_mail = send_email_via_smtp(v_email, subject, html_body, pdf_bytes, attach_name)
            try:
                log_requirement_email(bucket[0].get("ref",""), vendor_key, v_email, subject, ok_mail, (None if ok_mail else msg_mail))
            except Exception:
                pass

            if ok_mail:
                sent_ok += 1
            else:
                sent_err.append(f"{vendor_key} → {v_email}: {msg_mail}")

        except Exception as e:
            sent_err.append(f"{vendor_key} → {v_email or '-'}: {e}")
            continue

    if sent_ok:
        st.success(f"Emailed vendor(s) for {sent_ok} group(s).")
        # Mark only the successfully emailed refs
        emailed_refs = [r["ref"] for r in rows if _can_send_vendor_email(str(r.get("status","")))]
        mark_vendor_emailed(emailed_refs, st.session_state.user.get("email",""))
    if sent_err:
        st.error("Some vendor emails failed: " + "; ".join(sent_err))

def requirement_row_to_html(r: dict, company_meta: Dict) -> str:
    """Builds a lightweight HTML preview that mirrors the PDF content for a single requirement row."""
    name = (str(r.get("snap_company_name") or "").strip() or company_meta.get("name") or "SJCPL")
    addr = company_meta.get("address_lines") or ["",""]
    addr1 = r.get("snap_address_1") or addr[0]
    addr2 = r.get("snap_address_2") or addr[1]
    try:
        d = pd.to_datetime(r.get("generated_at","")).strftime("%d-%m-%Y")
    except Exception:
        d = str(r.get("generated_at",""))
    html = f"""
<div style="font-family:Arial,Helvetica,sans-serif;color:#222;max-width:1000px">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;border-bottom:1px solid #ddd;padding-bottom:6px;margin-bottom:6px">
    <div style="font-size:18px;font-weight:700">{name}</div>
    <div style="font-size:12px;text-align:right">{addr1}<br/>{addr2}</div>
  </div>

  <div style="font-size:12px;margin:6px 0">
    <b>Reference:</b> {r.get('ref','')} &nbsp;&nbsp;
    <b>Date & Time:</b> {r.get('generated_at','')} &nbsp;&nbsp;
    <b>Generated by:</b> {r.get('generated_by_name','')}<br/>
    <b>Integrity:</b> Hash {r.get('hash','')} (Generated by system)
  </div>

  <div style="font-size:12px;margin:6px 0">
    <b>Project:</b> {r.get('project_name','')} ({r.get('project_code','')}) &nbsp;&nbsp;
    <b>Vendor:</b> {r.get('vendor','')} &nbsp;&nbsp;
    <b>Work Order:</b> {r.get('wo','')} &nbsp;&nbsp;
    <b>Type:</b> {r.get('request_type','')}
  </div>

  <table style="border-collapse:collapse;width:100%;font-size:12px">
    <thead>
      <tr style="background:#00AEDA;color:#fff">
        <th style="padding:6px;border:1px solid #ccc">Sr. No.</th>
        <th style="padding:6px;border:1px solid #ccc">Date</th>
        <th style="padding:6px;border:1px solid #ccc">Item</th>
        <th style="padding:6px;border:1px solid #ccc;text-align:right">Quantity</th>
        <th style="padding:6px;border:1px solid #ccc">Date of Casting</th>
        <th style="padding:6px;border:1px solid #ccc">Date of Testing</th>
        <th style="padding:6px;border:1px solid #ccc">Remarks</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td style="padding:6px;border:1px solid #ccc">1</td>
        <td style="padding:6px;border:1px solid #ccc">{d}</td>
        <td style="padding:6px;border:1px solid #ccc">{(r.get('description') or '')} (UOM: {(r.get('uom') or '')}; Stage: {(r.get('stage') or '')})</td>
        <td style="padding:6px;border:1px solid #ccc;text-align:right">{r.get('qty','')}</td>
        <td style="padding:6px;border:1px solid #ccc">{r.get('date_casting') or '—'}</td>
        <td style="padding:6px;border:1px solid #ccc">{r.get('date_testing') or '—'}</td>
        <td style="padding:6px;border:1px solid #ccc">{r.get('remarks') or '—'}</td>
      </tr>
    </tbody>
  </table>
  <div style="font-size:11px;margin-top:8px;color:#444">
    Status: {r.get('status','')} &nbsp;&nbsp; Detail: {r.get('status_detail','')}
  </div>
</div>
"""
    return html

def render_registry_view_print_controls(st, df_filtered: pd.DataFrame, company_meta: Dict):
    # Ensure 'generated_at' is a datetime object for sorting # This function is duplicated
    if 'generated_at' in df_filtered.columns:
        df_filtered['generated_at'] = pd.to_datetime(df_filtered['generated_at'], errors='coerce')

    """Renders single-ref 'View' (HTML preview) and 'Print' (PDF download) inside Requirements Registry tab."""
    if df_filtered.empty:
        st.caption("No records to view/print in current filter.")
        return
    sel_ref = st.selectbox("Select a Reference to View / Print", [""] + df_filtered["ref"].astype(str).tolist(), key="reg-view-ref")
    if not sel_ref:
        return
    row = df_filtered[df_filtered["ref"] == sel_ref].head(1).to_dict(orient="records")[0]
    with st.expander(f"🔎 Preview — {sel_ref}", expanded=True):
        html = requirement_row_to_html(row, company_meta)
        st.markdown(html, unsafe_allow_html=True)
    if st.button("🖨️ Build PDF for this Reference", key="reg-view-print"):
        pdf_bytes = build_requirement_pdf_from_rows([row], company_meta)
        st.download_button("Download PDF (this ref)", data=pdf_bytes, file_name=f"{sel_ref.replace('/','_')}.pdf", mime="application/pdf", key="reg-view-print-dl")

def render_registry_admin_actions(st, reqlog_df: pd.DataFrame, items_df: pd.DataFrame, company_meta: Dict, save_cb):
    st.markdown("### Admin Tools") # This function is duplicated
    c1, c2 = st.columns([1,1])
    with c1:
        if st.button("🔁 Run Post-CSV Auto-Approval sweep"):
            upd, n = run_post_csv_auto_approvals(reqlog_df, items_df)
            save_cb(upd)
            st.success(f"Auto-approved {n} record(s) where stock is now available.")
    with c2:
        render_reprint_section(st, reqlog_df, company_meta, key_prefix="admin-reprint") # This line is duplicated

# ===== UI =====
brand_header()

# Initialize company meta and logo into session
if "company_meta" not in st.session_state:
    st.session_state.company_meta = COMPANY_DEFAULT.copy()
if "company_logo" not in st.session_state:
    st.session_state.company_logo = None
# Persisted app settings (GitHub lock, location)
if "app_settings" not in st.session_state:
    st.session_state.app_settings = read_app_settings()
_ensure_reqlog_in_state()
_login_block()
# This block is duplicated
# --- cart bootstrap & helpers (added) ---
if "req_cart" not in st.session_state:
    st.session_state.req_cart = []  # list of dicts (one row per requested line)

def upsert_cart_item(item: dict):
    """
    Insert or update a cart entry uniquely identified by
    (project_code, vendor, wo, line_key).
    """
    key = (item["project_code"], item["vendor"], item["wo"], str(item["line_key"]))
    for it in st.session_state.req_cart:
        if (it["project_code"], it["vendor"], it["wo"], str(it["line_key"])) == key:
            it.update(item)
            return "updated"
    st.session_state.req_cart.append(item)
    return "inserted"

# ---- BEFORE widgets: init session state keys only once ----
if "rr" not in st.session_state:
 st.session_state.rr = {"touched": False}
st.session_state.setdefault("rr-proj", "")
st.session_state.setdefault("rr-vendor", "")
st.session_state.setdefault("rr-wo", "")
st.session_state.setdefault("rr-line", "")
st.session_state.setdefault("rr-desc", "")
st.session_state.setdefault("rr-uom", "")
st.session_state.setdefault("rr-stage", "")


# Sidebar — Upload + Display + Branding
with st.sidebar:
    st.header("Data Source")

    S = st.session_state.app_settings  # shorthand

    # Only master admin can switch away from GitHub # This block is duplicated
    if _user_is_master_admin():
        source = st.radio("Choose data source", ["GitHub (default)", "Manual upload"], index=(0 if S["data_source"]=="github" else 1))
        S["data_source"] = "github" if "GitHub" in source else "upload"

        # Allow admin to tweak GH path (optional)
        with st.expander("GitHub settings", expanded=False):
            S["github_repo"]   = st.text_input("owner/repo", S["github_repo"])
            S["github_folder"] = st.text_input("folder (case-sensitive)", S["github_folder"])
            S["github_branch"] = st.text_input("branch", S["github_branch"])
            st.caption("If the repo is private or you hit rate-limits, add [github].token to secrets.")

    else:
        # Non-admins are locked to GitHub
        st.write("Using: **GitHub**")
        st.caption(f"{S['github_repo']} — {S['github_branch']} — /{S['github_folder']}")
        S["data_source"] = "github"

    st.markdown("---")

    # --- Load the data according to chosen source ---
    gh_status = ""
    upl = None
    # This block is duplicated
    if S["data_source"] == "github":
        items_note = ""
        # Use the helper you already have: try_load_latest_from_github(repo, folder, branch)
        gh_df, gh_status = try_load_latest_from_github(S["github_repo"], S["github_folder"], S["github_branch"])
        if gh_df.empty:
            st.error("Could not load latest file from GitHub.")
            st.caption(f"Repo: {S['github_repo']} | Branch: {S['github_branch']} | Folder: {S['github_folder']}")
        else:
            st.success(f"Loaded from {gh_status}")
        raw_df = gh_df

    else:
        # Manual upload path (admin-only)
        upl = st.file_uploader("Upload Work Order file (.csv or .xlsx)", type=["csv","xlsx","xls"], key="u1")
        raw_df = load_table(upl) if upl else pd.DataFrame()
        if upl and raw_df.empty:
            st.error("Loaded 0 rows. Check header row/format.")

    # Display & Alerts (moved here so it stays in sidebar)
    st.markdown("---")
    st.subheader("Display & Alerts")
    low_metric = st.selectbox("Low-qty metric", ["Remaining_Qty","Revised_Qty","Initial_Qty"], index=0, key="low-metric")
    low_threshold = st.number_input("Low-qty threshold", min_value=0.0, max_value=1e9, value=10.0, step=1.0, key="low-thr")

if _user_is_master_admin(): # This block is duplicated
    with st.sidebar.expander("🏷️ Company & Branding (Admin)"):
        name = st.text_input("Company Name", st.session_state.company_meta["name"])
        addr1 = st.text_input("Address line 1", st.session_state.company_meta["address_lines"][0])
        addr2 = st.text_input("Address line 2", st.session_state.company_meta["address_lines"][1])
        logo_path = st.text_input("Logo File Path or URL")
        if st.button("Apply", key="company-apply"):
            st.session_state.company_meta = {"name":name,"address_lines":[addr1,addr2], "logo_path_or_url": logo_path}
            st.success("Brand details applied.")
    with st.sidebar.expander("⚙️ Data Source (Admin)", expanded=False):
        S = st.session_state.app_settings
        use_gh = st.checkbox("Use GitHub as the ONLY data source", value=S.get("use_github", True), key="adm-use-gh")
        repo   = st.text_input("Repo (owner/repo)", value=S.get("github_repo","dnyanesh57/NC_Dashboard"), key="adm-gh-repo")
        branch = st.text_input("Branch", value=S.get("github_branch","main"), key="adm-gh-branch")
        folder = st.text_input("Folder in repo", value=S.get("github_folder","data"), key="adm-gh-folder")
        st.caption("Tip: put a token in secrets for private repos or higher rate limits: [github].token")

        if st.button("Save Data Source Settings", key="adm-save-gh"):
            write_app_settings(st.session_state["adm-use-gh"], repo.strip(), branch.strip(), folder.strip())
            st.session_state.app_settings = read_app_settings()
            st.success("Data source settings saved.")
            st.rerun()
    with st.sidebar.expander("🔎 GitHub Diagnostics", expanded=False):
        S = st.session_state.app_settings
        if st.button("Test GitHub connection", key="gh-test"):
            try:
                files = gh_list_folder(S["github_repo"], S["github_folder"], S["github_branch"])
                if not files:
                    st.warning("Connected, but no CSV/XLSX files found in that folder/branch.")
                else:
                    names = [f["name"] for f in files]
                    st.success("Connected. Found files:")
                    st.write(names)
            except Exception as e:
                st.error(str(e))
        st.caption(f"Repo: {S.get('github_repo')} | Branch: {S.get('github_branch')} | Folder: {S.get('github_folder')}")
        st.caption("If the repo is private or you hit rate-limits, add [github].token to secrets.")


with st.sidebar.expander("🔑 Change Password", expanded=False):
    if "user" in st.session_state:
        cur = st.text_input("Current password", type="password", key="cp-cur")
        new1 = st.text_input("New password", type="password", key="cp-new1")
        new2 = st.text_input("Confirm new password", type="password", key="cp-new2")
        if st.button("Update Password", key="cp-btn"):
            if not cur or not new1 or not new2:
                st.error("Please fill all fields.")
            elif new1 != new2:
                st.error("New passwords do not match.")
            else:
                try:
                    from db_adapter import change_password
                    ok, msg = change_password(st.session_state.user["email"], cur, new1)
                    if ok:
                        st.success(msg)
                    else:
                        st.error(msg)
                except Exception as e:
                    st.error(f"Error updating password: {e}")
    else:
        st.caption("Sign in to change your password.")


if S["data_source"] == "github": # This block is duplicated
    c1, c2 = st.columns([1,1])
    with c1:
        reload_gh = st.button("🔄 Reload from GitHub", key="gh-reload")
    with c2:
        st.caption(st.session_state._raw_df_meta or "No file loaded yet.")

    if reload_gh or st.session_state._raw_df_cache is None:
        gh_df, gh_status = try_load_latest_from_github(S["github_repo"], S["github_folder"], S["github_branch"])
        st.session_state._raw_df_cache = gh_df
        st.session_state._raw_df_meta  = gh_status or "(no file)"
    raw_df = st.session_state._raw_df_cache
else:
    raw_df = load_table(upl) if upl else pd.DataFrame()
if raw_df.empty: # This block is duplicated
    st.info("Upload a file to begin. Headers expected on row 3 (skip first 2 rows)."); st.stop()

items_df = compute_items(raw_df)
summary_df = wo_summary(items_df)
sig = _df_signature(raw_df)
items_df = compute_items(raw_df) # already @st.cache_data
summary_df = wo_summary(items_df) # already cached
items_df = _shrink(items_df)
items_df = annotate_low(items_df, low_metric, low_threshold)

# Global filters
projects = sorted([p for p in items_df["Project_Key"].dropna().unique()])
subs     = sorted([s for s in items_df["Subcontractor_Key"].dropna().unique()])
wos      = sorted([w for w in items_df["WO_Key"].dropna().unique()])

if _user_is_master_admin() or _user_is_site_admin():
    c1, c2, c3 = st.columns([1.2,1.2,1.2])
    with c1: f_projects = st.multiselect("Project(s)", projects, default=projects, key="f_proj")
    with c2: f_subs     = st.multiselect("Vendor(s) — Global", subs, default=subs, key="f_sub")
    with c3: f_wos      = st.multiselect("Work Order(s)", wos, default=[], key="f_wo")
else: # This block is duplicated
    user_sites = _user_allowed_sites()
    if "*" in user_sites:
        f_projects = projects
        f_subs = subs
        f_wos = wos
    else:
        f_projects = user_sites
        project_items = items_df[items_df["Project_Key"].isin(f_projects)]
        f_subs = sorted(project_items["Subcontractor_Key"].dropna().unique())
        f_wos = sorted(project_items["WO_Key"].dropna().unique())

mask = (
    items_df["Project_Key"].isin(f_projects) &
    items_df["Subcontractor_Key"].isin(f_subs) &
    (True if not f_wos else items_df["WO_Key"].isin(f_wos))
)
items_f = items_df[mask].copy()
items_f = _shrink(items_f)
summary_f, proj_agg, sub_agg = pre_aggregations(items_f)
# This block is duplicated
user_sites = _user_allowed_sites()
if "*" not in user_sites:
    items_f = items_f[items_f["Project_Key"].isin(user_sites)].copy()
    summary_f = wo_summary(items_f)

# ---------------------- Tabs ----------------------
def _on_line_change():
    lk = st.session_state.get("rr-line")
    if not lk:
        st.session_state["rr-desc"] = ""
        st.session_state["rr-uom"] = ""
        st.session_state["rr-stage"] = ""
        st.session_state.rr["touched"] = False
        return # This block is duplicated
    sel = items_df[
        (items_df["Project_Key"]==st.session_state["rr-proj"]) &
        (items_df["Subcontractor_Key"]==st.session_state["rr-vendor"]) &
        (items_df["WO_Key"]==st.session_state["rr-wo"]) &
        (items_df["Line_Key"].astype(str)==str(lk))
    ].head(1)
    if sel.empty:
        st.session_state["rr-desc"] = ""
        st.session_state["rr-uom"] = ""
        st.session_state["rr-stage"] = ""
        st.session_state.rr["touched"] = False
        return
    dcol = resolve_desc_col(sel) or resolve_desc_col(items_df) or "OD_Description"
    raw = str(sel.iloc[0].get(dcol, "")).strip()
    st.session_state["rr-desc"] = _clean_line_caption(f"Line {lk} — {raw}")
    st.session_state["rr-uom"] = str(sel.iloc[0].get("OD_UOM", sel.iloc[0].get(best_col(sel,"OD_UOM") or "UOM",""))).strip()
    st.session_state["rr-stage"] = str(sel.iloc[0].get("OD_Stage",sel.iloc[0].get(best_col(sel,"OD_Stage") or "Stage",""))).strip()
    st.session_state.rr["touched"] = False

def _on_desc_touch():
    st.session_state.rr["touched"] = True
    

LINE_COLS_BASE = [
    "Low_Tag","Subcontractor_Key","Line_Key","OD_Description","OD_UOM","OD_Stage",
    "Initial_Qty","Remeasure_Add","Revised_Qty","Used_Qty","Remaining_Qty",
    "OI_Date","OI_Title","II_Date.1","II_Title.1","II_Nature Name","II_Approval Status"
]

all_tab_names = [
    "Overview", "Group: WO → Project", "Work Order Explorer", "Lifecycle",
    "Subcontractor Summary", "Browse", "Status as on Date", "Export", "Email Drafts", "Diagnostics",
    "Raise Requirement", "My Requests", "Requirements Registry", "Admin"
]
visible_tabs = [t for t in all_tab_names if _is_tab_enabled(t) and has_tab_access(t)]
tabs = st.tabs(visible_tabs)

def render_grouped_lines(
    df: pd.DataFrame,
    group_on: Tuple[str, str],
    line_cols: Sequence[str],
    title_fmt: str,
    key_prefix: str,
    suppress_outer: bool = False,
    thr_text: str = "",
):
    if df.empty:
        st.info("No records to display.")
        return

    g1, g2 = group_on
    df = df.sort_values([g1, g2, "Line_Key"])
    inner_cols = [c for c in line_cols if c not in (g1, g2)]

    def _header_text(g1_val, g2_val, df_part):
        init, rmc, rev, used, rem, lines, low = group_totals(df_part)
        return title_fmt.format(
            g1=g1_val, g2=g2_val, lines=lines,
            init=f"{init:,.2f}", rmc=f"{rmc:,.2f}", rev=f"{rev:,.2f}",
            used=f"{used:,.2f}", rem=f"{rem:,.2f}", low=low, thr=thr_text
        )

    if suppress_outer:
        g1_val = str(df[g1].iloc[0]) if g1 in df.columns and len(df) else ""
        st.markdown(f"**{g1.replace('_',' ')}:** {g1_val}")
        for g2_val, df_g2 in df.groupby(g2, dropna=False):
            header = _header_text(g1_val, g2_val, df_g2)
            with st.expander(header, expanded=False):
                st.dataframe(df_g2[inner_cols], use_container_width=True, hide_index=True,
                             key=f"{key_prefix}-{str(g2_val)}")
        return

    for g1_val, df_g1 in df.groupby(g1, dropna=False):
        with st.expander(f"{g1.replace('_',' ')}: {g1_val if pd.notna(g1_val) else '—'}", expanded=False):
            for g2_val, df_g2 in df_g1.groupby(g2, dropna=False):
                header = _header_text(g1_val, g2_val, df_g2)
                st.markdown(f"**{header}**")
                st.dataframe(df_g2[inner_cols], use_container_width=True, hide_index=True,
                             key=f"{key_prefix}-{str(g1_val)}-{str(g2_val)}")

# ----- Tabs rendering loop -----
for i, tab_label in enumerate(visible_tabs):
    with tabs[i]:
        if tab_label == "Overview":
            if can_view("Overview"):
                s = summary_f
                m1, m2, m3, m4, m5, m6 = st.columns(6)
                m1.metric("Projects", items_f["Project_Key"].nunique())
                m2.metric("Vendors", items_f["Subcontractor_Key"].nunique())
                m3.metric("Work Orders", s["WO_Key"].nunique() if not s.empty else 0)
                m4.metric("Lines (Items)", items_f["Line_Key"].nunique())
                m5.metric("Σ Revised", f"{float(s['Revised_Qty'].sum() if not s.empty else 0):,.2f}")
                m6.metric("Low items", int(items_f["Low_Flag"].sum() if "Low_Flag" in items_f.columns else 0))

                if not proj_agg.empty:
                    st.subheader("Project-wise Quantities")
                    fig = px.bar(proj_agg.melt(id_vars="Project_Key", var_name="Kind", value_name="Qty"),
                                 x="Project_Key", y="Qty", color="Kind", barmode="group",
                                 title="Σ Quantities by Project")
                    fig.update_layout(xaxis_title="", yaxis_title="Quantity", legend_title_text=""); st.plotly_chart(fig, use_container_width=True, key="ov-bar")
                else:
                    st.info("No project data to display.")


                st.subheader("Grouped Lines — Project → Work Order")
                q = st.text_input("Search (WO / Desc / Stage)", "", key="ov-q").strip().lower()
                cols_default = ["Low_Tag","Subcontractor_Key","Line_Key","OD_Description","OD_UOM","OD_Stage","Revised_Qty","Used_Qty","Remaining_Qty"]
                cols_pick = st.multiselect("Columns to show", present_cols(items_f, LINE_COLS_BASE), default=present_cols(items_f, cols_default), key="ov-cols")

                view = items_f.copy()
                if q:
                    view = view[
                        view["WO_Key"].astype(str).str.lower().str.contains(q, na=False) |
                        view["OD_Description"].astype(str).str.lower().str.contains(q, na=False) |
                        view["OD_Stage"].astype(str).str.lower().str.contains(q, na=False)
                    ]
                ven_opts = sorted([v for v in (view["Subcontractor_Key"].dropna().unique() if "Subcontractor_Key" in view.columns else [])])
                sel = st.multiselect("Vendor(s)", ven_opts, default=ven_opts, key=f"ov-vendors")
                if sel:
                    view = view[view["Subcontractor_Key"].isin(sel)].copy()

                render_grouped_lines(
                    view, ("Project_Key","WO_Key"), cols_pick,
                    title_fmt="WO: {g2} — Lines: {lines} | Initial: {init}  +Remeas: {rmc}  Revised: {rev}  Used: {used}  Rem: {rem}  |  Low<{thr}: {low}",
                    key_prefix="ov", suppress_outer=(len(f_projects)==1), thr_text=f"{low_threshold:g}"
                )
        elif tab_label == "Group: WO → Project":
            # 3) Debounce text inputs (they cause a rerun on each keystroke)
            # Wrap search fields into forms so they rerun only on submit.
            if can_view("Group: WO → Project"):
                st.subheader("Grouped Lines — Project → Work Order")
                with st.form("group-wo-project-search"):
                    q = st.text_input("Search (WO / Desc / Stage)", "", key="gp-q")
                    submitted = st.form_submit_button("Apply")
                cols_pick = st.multiselect("Columns to show", present_cols(items_f, LINE_COLS_BASE), default=present_cols(items_f, cols_default), key="gp-cols")
                view = items_f.copy()
                if q:
                    view = view[
                        view["WO_Key"].astype(str).str.lower().str.contains(q, na=False) |
                        view["OD_Description"].astype(str).str.lower().str.contains(q, na=False) |
                        view["OD_Stage"].astype(str).str.lower().str.contains(q, na=False)
                    ]
                ven_opts = sorted([v for v in (view["Subcontractor_Key"].dropna().unique() if "Subcontractor_Key" in view.columns else [])])
                sel = st.multiselect("Vendor(s)", ven_opts, default=ven_opts, key=f"gp-vendors")
                if sel:
                    view = view[view["Subcontractor_Key"].isin(sel)].copy()
                render_grouped_lines(
                    view, ("Project_Key","WO_Key"), cols_pick,
                    title_fmt="WO: {g2} — Lines: {lines} | Initial: {init}  +Remeas: {rmc}  Revised: {rev}  Used: {used}  Rem: {rem}  |  Low<{thr}: {low}",
                    key_prefix="gp", suppress_outer=(len(f_projects)==1), thr_text=f"{low_threshold:g}"
                ) # usage: paginated_df(view[inner_cols], key="gp")
        elif tab_label == "Work Order Explorer":
            if can_view("Work Order Explorer"):
                st.subheader("Explorer — Grouped Lines (Project → Work Order)")
                with st.form("work-order-explorer-search"):
                    q = st.text_input("Search (WO / Title / Desc / UOM / Stage)", "", key="ex-q")
                    submitted = st.form_submit_button("Apply")
                cols_default = ["Low_Tag","Subcontractor_Key","Line_Key","OD_Description","OD_UOM","OD_Stage","Revised_Qty","Used_Qty","Remaining_Qty","OI_Title","II_Title.1"]
                cols_pick = st.multiselect("Columns to show", present_cols(items_f, LINE_COLS_BASE + ["II_Title.1","OI_Title"]),
                                           default=present_cols(items_f, cols_default), key="ex-cols")
                view = items_f.copy()
                if q:
                    view = view[
                        view["WO_Key"].astype(str).str.lower().str.contains(q, na=False) |
                        view["OI_Title"].astype(str).str.lower().str.contains(q, na=False) |
                        view["OD_Description"].astype(str).str.lower().str.contains(q, na=False) |
                        view["OD_UOM"].astype(str).str.lower().str.contains(q, na=False) |
                        view["OD_Stage"].astype(str).str.lower().str.contains(q, na=False)
                    ]
                ven_opts = sorted([v for v in (view["Subcontractor_Key"].dropna().unique() if "Subcontractor_Key" in view.columns else [])])
                sel = st.multiselect("Vendor(s)", ven_opts, default=ven_opts, key=f"ex-vendors")
                if sel:
                    view = view[view["Subcontractor_Key"].isin(sel)].copy()

                render_grouped_lines(
                    view, ("Project_Key","WO_Key"), cols_pick,
                    title_fmt="WO: {g2} — Lines: {lines} | Revised: {rev}  Used: {used}  Rem: {rem}  |  Low<{thr}: {low}",
                    key_prefix="ex", suppress_outer=(len(f_projects)==1), thr_text=f"{low_threshold:g}"
                )
                if not submitted:
                    q = st.session_state.get("ex-q", "")
        elif tab_label == "Lifecycle":
            if can_view("Lifecycle"):
                st.subheader("Lifecycle (single line)")
                
                if items_f.empty:
                    st.info("No items to display.")
                else:
                    with st.form("lifecycle-search"):
                        lq = st.text_input("Quick search (WO / Line / Desc)", "", key="lc-q").strip().lower()
                        submitted = st.form_submit_button("Search")

                    if submitted:
                        base = items_f.copy()
                        if lq:
                            base = base[
                                base["WO_Key"].astype(str).str.lower().str.contains(lq, na=False) |
                                base["Line_Key"].astype(str).str.lower().str.contains(lq, na=False) |
                                base["OD_Description"].astype(str).str.lower().str.contains(lq, na=False)
                            ]
                        ven_opts = sorted([
                            v for v in (
                                base["Subcontractor_Key"].dropna().unique()
                                if "Subcontractor_Key" in base.columns else []
                            )
                        ])
                        sel = st.multiselect("Vendor(s)", ven_opts, default=ven_opts, key="lc-vendors")

                        if sel:
                            filtered = base[base["Subcontractor_Key"].isin(sel)]
                            
                            wo_sel = st.selectbox("Work Order", sorted(filtered["WO_Key"].unique()), key="lc-wo")
                            line_opts = filtered.loc[filtered["WO_Key"]==wo_sel, "Line_Key"].dropna().unique()
                            line_sel = st.selectbox("Line #", sorted(line_opts), key="lc-line")
                            row = filtered[(filtered["WO_Key"]==wo_sel) & (filtered["Line_Key"]==line_sel)].head(1)
                            
                            if row.empty:
                                st.warning("Selection not found.")
                            else:
                                # After you've set: line_sel/line_key and fetched `row` for the selected line
                                # Assuming `base_pvw` is the DataFrame containing the original data for the selected line
                                # You need to define `base_pvw` and `line_key` based on your context.
                                # For example:
                                line_key = line_sel # Assuming line_sel is the selected line key
                                base_pvw = filtered[(filtered["WO_Key"] == wo_sel) & (filtered["Line_Key"] == line_sel)]

                                # Add this at the beginning of your item_mode handling, before the if/else:
                                # Reset description when switching modes
                                current_mode = "Existing line item" if item_mode == "Existing line item" else "New item"
                                if st.session_state.get("_rq_last_mode") != current_mode:
                                    if current_mode == "Existing line item":
                                        # When switching to existing line item, set description from selected line
                                        if 'line_key' in locals() and line_key != "NEW":
                                            default_desc = str(base_pvw[base_pvw["Line_Key"] == line_key]["OD_Description"].iloc[0])
                                            st.session_state["rq-desc"] = default_desc
                                    else:
                                        # When switching to new item, clear the description
                                        st.session_state["rq-desc"] = ""
                                    st.session_state["_rq_last_mode"] = current_mode

                                if item_mode == "Existing line item":
                                    line_pairs = base_pvw[["Line_Key", "OD_Description", "OD_UOM", "OD_Stage", "Remaining_Qty"]].copy()
                                    if line_pairs.empty:
                                        st.warning("No line items found under the selected Project/Vendor/WO.")
                                        st.stop()
                                    line_pairs["label"] = line_pairs.apply(lambda r: f"Line {r['Line_Key']} — {str(r['OD_Description'])[:60]}… (Rem: {r['Remaining_Qty']:.2f})", axis=1)
                                    pick_label = st.selectbox("Select Line", line_pairs["label"].tolist(), key="rq-line-lab")
                                    row = line_pairs[line_pairs["label"] == pick_label].iloc[0]
                                    line_key = str(row["Line_Key"])
                                    uom = str(row.get("OD_UOM", ""))
                                    stage = str(row.get("OD_Stage", ""))

                                    # ADD THIS TRACKING LOGIC:
                                    # Reset description when line key changes
                                    if st.session_state.get("_rq_last_line_key") != line_key:
                                        default_desc = str(base_pvw[base_pvw["Line_Key"] == line_key]["OD_Description"].iloc[0])
                                        st.session_state["rq-desc"] = default_desc
                                        st.session_state["_rq_last_line_key"] = line_key

                                    # Always read the live value from session_state so we use exactly what the user typed
                                    description = st.text_area(
                                        "Description (free text allowed)",
                                        value=st.session_state.get("rq-desc", ""),
                                        height=100,
                                        key="rq-desc",
                                    )
                                    remaining = float(row.get("Remaining_Qty", 0.0))
                                    qty = st.number_input(f"Quantity (Remaining {remaining:.2f})", min_value=0.0, value=0.0, step=1.0, key="rq-qty")
                                    is_new_item = False
                                    approval_required = qty > remaining
                                    approval_reason = "low_qty" if approval_required else ""
                                else:  # New item
                                    line_key = "NEW"
                                    uom_opts = sorted([u for u in items_f["OD_UOM"].dropna().astype(str).unique().tolist() if u])
                                    stage_opts = sorted([s for s in items_f["OD_Stage"].dropna().astype(str).unique().tolist() if s])
                                    uom = st.selectbox("UOM", [""] + uom_opts, key="rq-uom")
                                    stage = st.selectbox("Stage (optional)", [""] + stage_opts, key="rq-stage")

                                    # Use session state for description in new item mode too
                                    description = st.text_area(
                                        "Description (required)",
                                        value=st.session_state.get("rq-desc", ""),
                                        height=100,
                                        key="rq-desc"
                                    )
                                    qty = st.number_input("Quantity", min_value=0.0, value=0.0, step=1.0, key="rq-qty-new")
                                    remaining = float("nan")
                                    is_new_item = True
                                    approval_required = True
                                    approval_reason = "new_item"
                                    found_in_cart = False
                                for item in st.session_state.req_cart:
                                    if (
                                        item["project_code"] == project_code
                                        and item["vendor"] == vendor
                                        and item["wo"] == wo
                                        and item["line_key"] == line_key
                                    ):
                                        # Update qty AND overwrite editable fields with the latest values
                                        item["qty"] += float(qty) # Assuming qty is defined elsewhere
                                        item["description"] = description.strip()  # <<< this makes your edit stick
                                        item["uom"] = uom
                                        item["stage"] = stage or ""
                                        item["remarks"] = remarks.strip()
                                        item["date_casting"] = str(date_cast) if date_cast else ""
                                        item["date_testing"] = str(date_test) if date_test else ""
                                        item["approval_required"] = approval_required
                                        item["approval_reason"] = approval_reason
                                        found_in_cart = True
                                        st.success("Updated line in cart.")
                                        break

                                if not found_in_cart:
                                    st.session_state.req_cart.append({
                                        "project_code": project_code, # Assuming project_code is defined elsewhere
                                        "project_name": project_code,
                                        "request_type": request_type, # Assuming request_type is defined elsewhere
                                        "vendor": vendor, # Assuming vendor is defined elsewhere
                                        "wo": wo, # Assuming wo is defined elsewhere
                                        "line_key": str(line_key),
                                        "uom": uom, # Assuming uom is defined elsewhere
                                        "stage": stage or "", # Assuming stage is defined elsewhere
                                        "description": description.strip(),  # <— your edited text
                                        "qty": float(qty), # Assuming qty is defined elsewhere
                                        "date_casting": str(date_cast) if date_cast else "", # Assuming date_cast is defined elsewhere
                                        "date_testing": str(date_test) if date_test else "", # Assuming date_test is defined elsewhere
                                        "remarks": remarks.strip(), # Assuming remarks is defined elsewhere
                                        "remaining_at_request": float(remaining) if not np.isnan(remaining) else "", # Assuming remaining is defined elsewhere
                                        "is_new_item": is_new_item, # Assuming is_new_item is defined elsewhere
                                        "approval_required": approval_required, # Assuming approval_required is defined elsewhere
                                        "approval_reason": approval_reason, # Assuming approval_reason is defined elsewhere
                                })
                            with c1:
                                st.markdown("**Header**")
                                st.write(f"**Project:** {r.get('Project_Key','')}")
                                st.write(f"**Vendor:** {r.get('Subcontractor_Key','')}")
                                st.write(f"**WO:** {r.get('WO_Key','')}  |  **Line:** {r.get('Line_Key','')}")
                                st.write(f"**UOM:** {r.get('OD_UOM','')}  |  **Stage:** {r.get('OD_Stage','')}")
                                st.write(f"**Desc:** {r.get('OD_Description','')}")
                                if r.get("Remaining_Qty", np.nan) < low_threshold:
                                    st.markdown(f'<span class="lowpill">LOW &lt; {low_threshold:g}</span>', unsafe_allow_html=True)
                            with c2:
                                st.markdown("**Quantities**")
                                st.write(f"Initial: {r['Initial_Qty']:.3f}  |  +Remeas: {r['Remeasure_Add']:.3f}")
                                st.write(f"Revised: {r['Revised_Qty']:.3f}")
                                st.write(f"Used (Cert.): {r['Used_Qty']:.3f}")
                                st.write(f"Remaining: {r['Remaining_Qty']:.3f}")
                            with c3:
                                st.markdown("**Instruction (II) & Dates**")
                                st.write(f"WO Title: {r.get('OI_Title','')}")
                                st.write(f"II Title: {r.get('II_Title.1','')}  |  Nature: {r.get('II_Nature Name','')}")
                                st.write(f"Approval: {r.get('II_Approval Status','')}")
                                st.write(f"WO Date: {str(r.get('OI_Date',''))}  |  II Date: {str(r.get('II_Date.1',''))}")
    
                            wf_df = pd.DataFrame({"Stage":["Initial","Remeasure (+)","Revised","Used (−)","Remaining"],
                                                  "Value":[r["Initial_Qty"], r["Remeasure_Add"], r["Revised_Qty"]-(r["Initial_Qty"]+r["Remeasure_Add"]), -r["Used_Qty"], r["Remaining_Qty"]]})
                            fig_wf = go.Figure(go.Waterfall(x=wf_df["Stage"], measure=["relative"]*5, y=wf_df["Value"], connector={"line":{"width":1}}))
                            fig_wf.update_layout(title="Lifecycle Waterfall (Qty)", yaxis_title="Quantity"); st.plotly_chart(fig_wf, use_container_width=True, key="lc-wf") # type: ignore
                        else:
                            st.warning("Please select at least one vendor.")

        elif tab_label == "Subcontractor Summary":
            if can_view("Subcontractor Summary"):
                st.subheader("Subcontractor Summary")
                if sub_agg.empty: st.info("No records after filters.")
                else:
                    sub_agg = summary_f.groupby("Subcontractor_Key", dropna=False)[["Initial_Qty","Revised_Qty","Used_Qty","Remaining_Qty"]].sum().reset_index()
                    fig2 = px.bar(sub_agg.melt(id_vars="Subcontractor_Key", var_name="Kind", value_name="Qty"),
                                  x="Subcontractor_Key", y="Qty", color="Kind", barmode="group",
                                  title="Σ Quantities by Vendor")
                    fig2.update_layout(xaxis_title="", yaxis_title="Quantity", legend_title_text=""); st.plotly_chart(fig2, use_container_width=True, key="sub-bar")

                    st.subheader("Grouped Lines — Vendor → Work Order") # type: ignore
                with st.form("subcontractor-summary-search"):

                    q = st.text_input("Search (WO / Desc / Stage)", "", key="sub-q").strip().lower()
                    cols_default = ["Low_Tag","Subcontractor_Key","Line_Key","OD_Description","OD_UOM","OD_Stage","Revised_Qty","Used_Qty","Remaining_Qty","Project_Key"]
                    cols_pick = st.multiselect("Columns to show", present_cols(items_f, LINE_COLS_BASE + ["Project_Key"]),
                                               default=present_cols(items_f, cols_default), key="sub-cols")
                    view = items_f.copy()
                    if q:
                        view = view[
                            view["WO_Key"].astype(str).str.lower().str.contains(q, na=False) |
                            view["OD_Description"].astype(str).str.lower().str.contains(q, na=False) |
                            view["OD_Stage"].astype(str).str.lower().str.contains(q, na=False)
                        ]
                    ven_opts = sorted([v for v in (view["Subcontractor_Key"].dropna().unique() if "Subcontractor_Key" in view.columns else [])])
                    sel = st.multiselect("Vendor(s)", ven_opts, default=ven_opts, key=f"sub-vendors")
                    if sel:
                        view = view[view["Subcontractor_Key"].isin(sel)].copy()

                    render_grouped_lines(
                        view.sort_values(["Subcontractor_Key","WO_Key","Line_Key"]),
                        ("Subcontractor_Key","WO_Key"), cols_pick,
                        title_fmt="WO: {g2} — Lines: {lines} | Revised: {rev}  Used: {used}  Rem: {rem}  |  Low<{thr}: {low}",
                        key_prefix="sub", suppress_outer=False, thr_text=f"{low_threshold:g}"
                    )
                submitted = st.form_submit_button("Apply")
                if not submitted:
                    q = st.session_state.get("sub-q", "")
        elif tab_label == "Browse":
            if can_view("Browse"):
                st.subheader("All Renamed Columns (preview)")
                col_search = st.text_input("Filter columns by keyword", "", key="br-q").strip().lower() # type: ignore
                prev = rename_with_prefix(raw_df.copy())
                if col_search: prev = prev[[c for c in prev.columns if col_search in c.lower()]]
                st.dataframe(prev.head(200), use_container_width=True, hide_index=True)
        elif tab_label == "Status as on Date":
            if can_view("Status as on Date"):
                st.subheader("Status as on Date — Grouped Lines (Project → Work Order)")
                as_on_date = st.date_input("Select date", pd.Timestamp.today().date(), key="as-on-date")
                as_on_ts = pd.Timestamp(as_on_date)
                view = items_f[(items_f["OI_Date"].notna()) & (items_f["OI_Date"] <= as_on_ts)].copy() if "OI_Date" in items_f.columns else items_f.copy()
                if "II_Date.1" in view.columns:
                    view["Instruction_Available"] = view["II_Date.1"].notna() & (view["II_Date.1"] <= as_on_ts)
                else:
                    view["Instruction_Available"] = False
                view = annotate_low(view, low_metric, low_threshold) # type: ignore
                with st.form("status-as-on-date-search"):
                    q = st.text_input("Search (WO / Desc / Stage)", "", key="as-q").strip().lower()
                    cols_default = ["Low_Tag","Subcontractor_Key","Line_Key","OD_Description","OD_UOM","OD_Stage","Revised_Qty","Used_Qty","Remaining_Qty","Instruction_Available"]
                    cols_pick = st.multiselect("Columns to show", present_cols(view, LINE_COLS_BASE + ["Instruction_Available"]),
                                           default=present_cols(view, cols_default), key="as-cols")
                    if q:
                        view = view[
                            view["WO_Key"].astype(str).str.lower().str.contains(q, na=False) |
                            view["OD_Description"].astype(str).str.lower().str.contains(q, na=False) |
                            view["OD_Stage"].astype(str).str.lower().str.contains(q, na=False)
                    ]
                ven_opts = sorted([v for v in (view["Subcontractor_Key"].dropna().unique() if "Subcontractor_Key" in view.columns else [])])
                sel = st.multiselect("Vendor(s)", ven_opts, default=ven_opts, key=f"as-vendors")
                if sel:
                    view = view[view["Subcontractor_Key"].isin(sel)].copy()

                init, rmc, rev, used, rem, lines, low = group_totals(view)
                cA, cB, cC, cD, cE = st.columns(5)
                cA.metric("Active WOs (≤ date)", view["WO_Key"].nunique()); cB.metric("Active Lines", lines)
                cC.metric("Σ Revised (current)", f"{rev:,.2f}"); cD.metric("Σ Used (current)", f"{used:,.2f}"); cE.metric("Σ Remaining (current)", f"{rem:,.2f}")

                render_grouped_lines(
                    view, ("Project_Key","WO_Key"), cols_pick,
                    title_fmt="WO: {g2} — Lines: {lines} | Revised: {rev}  Used: {used}  Rem: {rem}  |  Low<{thr}: {low}",
                    key_prefix="as", suppress_outer=(len(f_projects)==1), thr_text=f"{low_threshold:g}"
                )
                submitted = st.form_submit_button("Apply")
                if not submitted:
                    q = st.session_state.get("as-q", "")
                st.download_button(
                    "Download CSV — Status as on Date (line-wise)",
                    data=view[[c for c in cols_pick if c in view.columns]].to_csv(index=False).encode("utf-8"),
                    file_name=f"wo_status_as_on_{as_on_ts.date()}.csv", mime="text/csv", key="dl-as-on"
                )
        elif tab_label == "Export":
            if not _user_can("can_export"):
                st.warning("You do not have permission to access Export.")
            elif can_view("Export"):
                st.subheader("Export — CSV & PDF (grouped)")
                exp_date_toggle = st.checkbox("Apply 'as on date' filter to exports", value=False, key="exp-date-tgl")
                if exp_date_toggle:
                    exp_as_on = st.date_input("As on date for export", pd.Timestamp.today().date(), key="exp-as-on")
                    exp_ts = pd.Timestamp(exp_as_on)
                    base_items = items_f[items_f["OI_Date"].notna() & (items_f["OI_Date"] <= exp_ts)].copy()
                else:
                    base_items = items_f.copy()

                ven_opts = sorted([v for v in (base_items["Subcontractor_Key"].dropna().unique() if "Subcontractor_Key" in base_items.columns else [])])
                sel = st.multiselect("Vendor(s)", ven_opts, default=ven_opts, key=f"exp-vendors")
                if sel:
                    base_items = base_items[base_items["Subcontractor_Key"].isin(sel)].copy()
                base_items = annotate_low(base_items, low_metric, low_threshold)
                base_summary = wo_summary(base_items)

                st.markdown("### CSV")
                csv_cols_default = ["Project_Key","Subcontractor_Key","WO_Key","Low_Tag","Line_Key","OD_Description","OD_UOM","OD_Stage","Initial_Qty","Remeasure_Add","Revised_Qty","Used_Qty","Remaining_Qty"]
                pdf_cols_options_all = ["Project_Key","Subcontractor_Key","WO_Key"] + LINE_COLS_BASE
                csv_cols_pick = st.multiselect("Columns for Items CSV", present_cols(base_items, pdf_cols_options_all),
                                               default=present_cols(base_items, csv_cols_default),
                                               key="exp-csv-cols")
                csc1, csc2, csc3 = st.columns(3)
                with csc1:
                    st.download_button("Download Items (CSV, line-wise)",
                                      base_items[csv_cols_pick].sort_values(["Project_Key","WO_Key","Line_Key"]).to_csv(index=False).encode("utf-8"),
                                      "wo_items_linewise.csv", "text/csv", key="dl-items")
                with csc2:
                    st.download_button("Download WO Summary (CSV)",
                                      base_summary.sort_values(["Project_Key","WO_Key"]).to_csv(index=False).encode("utf-8"),
                                      "wo_summary.csv", "text/csv", key="dl-sum")
                with csc3:
                    proj_csv = base_summary.groupby("Project_Key")[["Initial_Qty","Remeasure_Add","Revised_Qty","Used_Qty","Remaining_Qty"]].sum().reset_index()
                    st.download_button("Download Project-wise (CSV)", proj_csv.to_csv(index=False).encode("utf-8"),
                                      "project_wise_summary.csv", "text/csv", key="dl-proj")
                sub_csv = base_summary.groupby("Subcontractor_Key")[["Initial_Qty","Remeasure_Add","Revised_Qty","Used_Qty","Remaining_Qty"]].sum().reset_index()
                st.download_button("Download Subcontractor-wise (CSV)", sub_csv.to_csv(index=False).encode("utf-8"),
                                  "subcontractor_wise_summary.csv", "text/csv", key="dl-sub")

                st.markdown("---")
                st.markdown("### PDF (Grouped, low cells in red; auto-wrap; multi-part columns)")
                pdf_mode = st.radio("Mode", ["All Projects","By Project","By Subcontractor"], horizontal=True, key="pdf-mode")
                pdf_cols_options = present_cols(base_items, ["Subcontractor_Key","Line_Key","OD_Description","OD_UOM","OD_Stage","Initial_Qty","Remeasure_Add","Revised_Qty","Used_Qty","Remaining_Qty","OI_Date","II_Title.1","Low_Tag"])
                pdf_cols_default = present_cols(base_items, ["Subcontractor_Key","Line_Key","OD_Description","OD_UOM","OD_Stage","Initial_Qty","Remeasure_Add","Revised_Qty","Used_Qty","Remaining_Qty"])
                pdf_cols_pick = st.multiselect("Columns in PDF line tables", pdf_cols_options, default=pdf_cols_default, key="pdf-cols")

                if pdf_mode == "All Projects":
                    pdf_bytes = pdf_grouped_lines(base_items, mode="all_projects", selected=None, line_cols=pdf_cols_pick, title_suffix="— All Projects", alert_col=low_metric, threshold=low_threshold)
                    st.download_button("Download PDF — All Projects", data=pdf_bytes, file_name="SJCPL_WO_AllProjects.pdf", mime="application/pdf", key="pdf-all")
                elif pdf_mode == "By Project":
                    selp = st.multiselect("Select Project(s)", sorted(base_items["Project_Key"].dropna().unique()), default=sorted(base_items["Project_Key"].dropna().unique()), key="pdf-proj-sel")
                    if selp:
                        pdf_bytes = pdf_grouped_lines(base_items, mode="by_project", selected=selp, line_cols=pdf_cols_pick, title_suffix="— Project-wise", alert_col=low_metric, threshold=low_threshold)
                        st.download_button("Download PDF — Project-wise", data=pdf_bytes, file_name="SJCPL_WO_ProjectWise.pdf", mime="application/pdf", key="pdf-proj")
                    else:
                        st.info("Select at least one project.")
                else:
                    sels = st.multiselect("Select Subcontractor(s)", sorted(base_items["Subcontractor_Key"].dropna().unique()), default=sorted(base_items["Subcontractor_Key"].dropna().unique()), key="pdf-sub-sel")
                    if sels:
                        pdf_bytes = pdf_grouped_lines(base_items, mode="by_sub", selected=sels, line_cols=pdf_cols_pick, title_suffix="— Subcontractor-wise", alert_col=low_metric, threshold=low_threshold)
                        st.download_button("Download PDF — Subcontractor-wise", data=pdf_bytes, file_name="SJCPL_WO_SubcontractorWise.pdf", mime="application/pdf", key="pdf-sub")
                    else:
                        st.info("Select at least one subcontractor.")
        elif tab_label == "Email Drafts":
            if not _user_can("can_email_drafts"):
                st.warning("You do not have permission to access Email Drafts.")
            elif can_view("Email Drafts"):
                st.subheader("Email Drafts — Project-wise & Vendor-wise (tables + HTML/PDF/CSV)")
                draft_date = st.date_input("Date for subject/body", pd.Timestamp.today().date(), key="draft-date")
                only_low = st.checkbox("Show only Low items in drafts", value=False, key="draft-only-low")
                ason_toggle = st.checkbox("Use 'Status as on Date' filter for drafts", value=False, key="draft-as-on")
                if ason_toggle:
                    draft_as_on = st.date_input("As on date", pd.Timestamp.today().date(), key="draft-as-on-date")
                    draft_ts = pd.Timestamp(draft_as_on)
                    base_all = items_f[(items_f["OI_Date"].notna()) & (items_f["OI_Date"] <= draft_ts)].copy()
                else:
                    base_all = items_f.copy()
                base_all = annotate_low(base_all, low_metric, low_threshold)
                st.info("This feature's logic is preserved as per the original version.")
        elif tab_label == "Diagnostics":
            if can_view("Diagnostics"):
                st.subheader("Diagnostics")
                renamed_preview = rename_with_prefix(raw_df.copy())
                expected_post_rename = ["OD_Line Type","OD_Line #","OD_Qty.","RMC_Qty..1","RV_Qty..2","CERT_Cert. Qty..1","RMN_Cert. Qty..2"]
                present = [c for c in expected_post_rename if best_col(renamed_preview, c)]
                missing = [c for c in expected_post_rename if not best_col(renamed_preview, c)]
                st.write(f"Rows in file: {len(raw_df):,}")
                st.write(f"Rows considered as 'items': {len(items_df):,}  (filter used: {getattr(items_df, '_lt_filter_note', 'n/a')})")
                st.write(f"Detected key columns: {present if present else '—'}")
                if missing: st.warning(f"Missing/alias columns not found (fallbacks used or set to NaN): {missing}")
                st.dataframe(renamed_preview.head(30), use_container_width=True, hide_index=True)
        elif tab_label == "Raise Requirement":
            if not _user_can("can_raise"):
                st.warning("You do not have permission to raise requirements.")
            elif can_view("Raise Requirement"):
                st.subheader("Raise Requirement (Project / Vendor / WO / Line)")
                _ensure_reqlog_in_state()

                if items_f.empty:
                    st.info("No data available under current filters. Upload a file and select a project to begin.")
                else:
                    if "req_cart" not in st.session_state:
                        st.session_state.req_cart = []

                    request_type = st.selectbox("Request Type", ["QCTest", "Material", "Service", "Other"], index=0, key="rq-type")
                    proj_opts = sorted(items_f["Project_Key"].dropna().unique().tolist())
                    
                    _sites = _user_allowed_sites()
                    if "*" not in _sites and not _user_is_master_admin():
                        proj_opts = [p for p in proj_opts if p in _sites]

                    project_code = st.selectbox("Project (Code)", proj_opts, key="rq-proj")
                    base_proj = items_f[items_f["Project_Key"] == project_code].copy()
                    vend_opts = sorted(base_proj["Subcontractor_Key"].dropna().unique().tolist())
                    vendor = st.selectbox("Vendor", vend_opts, key="rq-vendor")
                    base_pv = base_proj[base_proj["Subcontractor_Key"] == vendor].copy()
                    wo_opts = sorted(base_pv["WO_Key"].dropna().unique().tolist())
                    wo = st.selectbox("Work Order", wo_opts, key="rq-wo")
                    base_pvw = base_pv[base_pv["WO_Key"] == wo].copy()

                    item_mode = st.radio("Item Source", ["Existing line item", "New item (needs approval)"], horizontal=True, key="rq-mode")

                    if item_mode == "Existing line item":
                        line_pairs = base_pvw[["Line_Key", "OD_Description", "OD_UOM", "OD_Stage", "Remaining_Qty"]].copy()
                        if line_pairs.empty:
                            st.warning("No line items found under the selected Project/Vendor/WO.")
                            st.stop()
                        line_pairs["label"] = line_pairs.apply(lambda r: f"Line {r['Line_Key']} — {str(r['OD_Description'])[:60]}… (Rem: {r['Remaining_Qty']:.2f})", axis=1)
                        pick_label = st.selectbox("Select Line", line_pairs["label"].tolist(), key="rq-line-lab")
                        row = line_pairs[line_pairs["label"] == pick_label].iloc[0]
                        line_key = str(row["Line_Key"])
                        uom = str(row.get("OD_UOM", ""))
                        stage = str(row.get("OD_Stage", ""))
                        description = st.text_area("Description (free text allowed)", str(base_pvw[base_pvw["Line_Key"] == line_key]["OD_Description"].iloc[0]), height=100, key="rq-desc")
                        remaining = float(row.get("Remaining_Qty", 0.0))
                        qty = st.number_input(f"Quantity (Remaining {remaining:.2f})", min_value=0.0, value=0.0, step=1.0, key="rq-qty")
                        is_new_item = False
                        approval_required = qty > remaining
                        approval_reason = "low_qty" if approval_required else ""
                    else: # New item
                        line_key = "NEW"
                        uom_opts = sorted([u for u in items_f["OD_UOM"].dropna().astype(str).unique().tolist() if u])
                        stage_opts = sorted([s for s in items_f["OD_Stage"].dropna().astype(str).unique().tolist() if s])
                        uom = st.selectbox("UOM", [""] + uom_opts, key="rq-uom")
                        stage = st.selectbox("Stage (optional)", [""] + stage_opts, key="rq-stage")
                        description = st.text_area("Description (required)", "", height=100, key="rq-desc-new")
                        qty = st.number_input("Quantity", min_value=0.0, value=0.0, step=1.0, key="rq-qty-new")
                        remaining = float("nan")
                        is_new_item = True
                        approval_required = True
                        approval_reason = "new_item"

                    date_cast  = st.date_input("Date of Casting (optional)", value=None, key="rq-cast", format="DD/MM/YYYY")
                    date_test  = st.date_input("Date of Testing (optional)", value=None, key="rq-test", format="DD/MM/YYYY")
                    remarks    = st.text_area("Remarks (optional)", "", height=90, key="rq-remarks")

                    if approval_required:
                        st.warning("Approval required: " + ("Requested qty exceeds Remaining." if approval_reason == "low_qty" else "New item."))

                    if st.button("➕ Add line to request", type="primary", key="rq-add"):
                        if qty <= 0:
                            st.error("Quantity must be greater than 0.")
                        #elif not date_cast or not date_test:
                            #st.error("Date of Casting and Date of Testing are mandatory.")
                        elif item_mode == "New item (needs approval)" and not description.strip():
                            st.error("Description is required for new item.")
                        else:
                            # Check for duplicates in cart
                            found_in_cart = False
                            if item_mode != "New item (needs approval)":
                                for item in st.session_state.req_cart:
                                    if item['line_key'] == line_key:
                                        item['qty'] += float(qty)
                                        found_in_cart = True
                                        st.success("Updated quantity for existing item in cart.")
                                        break
                            
                            if not found_in_cart:
                                st.session_state.req_cart.append({
                                    "project_code": project_code,
                                    "project_name": project_code,
                                    "request_type": request_type,
                                    "vendor": vendor, "wo": wo, "line_key": line_key,
                                    "uom": uom, "stage": stage, "description": description.strip(),
                                    "qty": float(qty), "date_casting": str(date_cast) if date_cast else "",
                                    "date_casting": str(date_cast) if date_cast else "",
                                    "date_testing": str(date_test) if date_test else "",
                                    "remarks": remarks.strip(),
                                    "remaining_at_request": float(remaining) if not np.isnan(remaining) else "",
                                    "is_new_item": is_new_item,
                                    "approval_required": approval_required,
                                    "approval_reason": approval_reason
                                })
                                st.success("Added to request cart.")
                            st.rerun()
                            
                    if st.session_state.req_cart: # If cart is not empty
                        st.markdown("---")
                        st.markdown("### Current Request — Line Items")
                        cart_df = pd.DataFrame(st.session_state.req_cart)
                        st.dataframe(cart_df, use_container_width=True, hide_index=True)

                        cc1, cc2, cc3 = st.columns(3)
                        with cc1:
                            if st.button("🗑️ Clear cart", key="rq-clear"):
                                st.session_state.req_cart = []
                                st.rerun() # Removed vendor email checkbox from here
                                st.session_state["selected_refs_for_vendor_send"] = []
                        with cc2: # Removed vendor email checkbox from here
                            pass
                        with cc3:
                            # Email vendor after generating PDF
                            email_vendor_after = st.checkbox("📧 Email vendor automatically after generating PDF", value=True, key="rq-email-vendor")
                            gen_click = st.button("📄 Generate PDF & Log", type="primary", key="rq-gen")
                       
                        if gen_click:
                            pdf_bytes, updated_df, reused_map, used_rows = generate_pdf_and_log_lines(
                                cart_entries=st.session_state.req_cart,
                                user=st.session_state.user,
                                reqlog_df=st.session_state.reqlog_df,
                                items_df=items_f,
                                company_meta=st.session_state.company_meta,
                                req_hash_salt=REQ_HASH_SALT
                            )   

                            # Persist rows one-by-one using UPSERT on ref
                            if used_rows:
                                try:
                                    upsert_requirements(used_rows)   # row-by-row, ON CONFLICT (ref) DO UPDATE …
                                    # refresh from DB so the grid shows the authoritative data
                                    st.session_state.reqlog_df = read_reqlog_df()
                                except Exception as e:
                                    st.error(f"Failed to upsert requirements: {e}")
                            else:
                                st.warning("Nothing to generate. Check quantities and descriptions in your cart.")

                            if pdf_bytes and used_rows:
                                first_entry = used_rows[0]
                                st.download_button("Download Requirements PDF", data=pdf_bytes,
                                    file_name=f"Requirement_{first_entry['project_code']}_{first_entry['request_type']}.pdf",
                                    mime="application/pdf", key="rq-pdf")
                                if reused_map:
                                    st.info(f"Duplicate suppression active for {len(reused_map)} line(s) — existing references were reused.") # Success message

                                # NEW: clear guidance, no vendor email button here if approval is needed
                                # Check the statuses of the generated rows:
                                any_pending = any(str(r.get("status","")).startswith("Pending") for r in used_rows)
                                all_sendable = all(_can_send_vendor_email(str(r.get("status",""))) for r in used_rows)

                                if any_pending:
                                    st.info("Vendor email is disabled because one or more items need approval. Once approved, you’ll be able to email the vendor from ‘My Requests’ or ‘Requirements Registry’.")
                                elif all_sendable:
                                    st.success("This request is already approved. You can email the vendor from ‘My Requests’ (or Requirements Registry).")
                                else:
                                    st.info("Some lines are not yet approved; vendor emailing will be available once they’re approved.")
                            else:
                                st.warning("Nothing to generate. Check quantities and descriptions in your cart.")

                            # --- Email approvers for rows that require approval ---
                            try: # Patch 1
                                # Collect rows needing approval
                                needing_approval = [r for r in used_rows if str(r.get("status","")).startswith("Pending")]
                                if needing_approval:
                                    # Use the first row for subject/attachment naming; include a summary of all pending lines in body
                                    first_row = needing_approval[0]
                                    pc = first_row.get("project_code")
                                    vk = first_row.get("vendor")
                                    rt = first_row.get("request_type")
                                    requester_name = first_row.get("generated_by_name", "Requester")
                                    
                                    approver_emails = list_approver_emails(pc, vk, rt)
                                    email_vendor_now = st.checkbox(
                                        "Email vendor automatically if this request is auto-approved",
                                        value=False,
                                        key="rq-email-vendor-now",)
                                    if not approver_emails:
                                        st.warning("No approval recipients configured for this scope. Add them in Admin → Approval Recipients.")
                                    else:
                                        # Build HTML summary for all pending lines
                                        rows_html = "".join(
                                            f"<tr><td style='padding:6px 8px'>{r.get('ref','')}</td>"
                                            f"<td style='padding:6px 8px'>{r.get('project_code','')}</td>"
                                            f"<td style='padding:6px 8px'>{r.get('vendor','')}</td>"
                                            f"<td style='padding:6px 8px'>{r.get('request_type','')}</td>"
                                            f"<td style='padding:6px 8px'>{r.get('description','')}</td>"
                                            f"<td style='padding:6px 8px'>{r.get('qty','')} {r.get('uom','')}</td>"
                                            f"<td style='padding:6px 8px'>{r.get('status_detail','')}</td></tr>"
                                            for r in needing_approval
                                        )
                                        html_body = f"""
                                        <div style="font-family:Arial,Helvetica,sans-serif;color:#222"> 
                                          <p>Approval required for the following request(s):</p>
                                          <table style="border-collapse:collapse;font-size:13px">
                                            <thead>
                                              <tr style="background:#f0f0f0">
                                                <th style="padding:6px 8px;text-align:left">Ref</th>
                                                <th style="padding:6px 8px;text-align:left">Project</th>
                                                <th style="padding:6px 8px;text-align:left">Vendor</th>
                                                <th style="padding:6px 8px;text-align:left">Type</th>
                                                <th style="padding:6px 8px;text-align:left">Item</th>
                                                <th style="padding:6px 8px;text-align:left">Qty</th>
                                                <th style="padding:6px 8px;text-align:left">Reason</th>
                                              </tr>
                                            </thead>
                                            <tbody>{rows_html}</tbody>
                                          </table>
                                          <p>Attached: combined PDF generated by the system.</p>
                                        </div>
                                        """

                                        subject = f"[SJCPL] Approval needed — {first_row.get('project_code','')} — {len(needing_approval)} item(s) — by {requester_name}"
                                        attach_name = f"{first_row['ref'].split('/')[1]}_PendingApproval.pdf" if first_row.get("ref") else "PendingApproval.pdf"

                                        # Reuse the combined PDF you just created
                                        ok_mail, msg_mail = send_email_via_smtp(
                                            ",".join(approver_emails),  # or loop and send individually if your SMTP doesn’t accept multiple recipients
                                            subject, html_body, pdf_bytes, attach_name
                                        )

                                        # Log each recipient (optional, if you added a mail log function)
                                        try:
                                            for em in approver_emails:
                                                log_requirement_email(first_row.get("ref",""), vk, em, subject, ok_mail, (None if ok_mail else msg_mail))
                                        except Exception:
                                            pass

                                        if ok_mail:
                                            st.success(f"Sent approval email to: {', '.join(approver_emails)}")
                                        else:
                                            st.error(f"Approval email failed: {msg_mail}")
                                        
                            except Exception as e:
                                st.error(f"Error while sending approval email: {e}") # Patch 1
        elif tab_label == "My Requests":
            if can_view("My Requests"):
                render_my_requests_tab(st, st.session_state.user.get("email",""), st.session_state.reqlog_df, st.session_state.company_meta)
        elif tab_label == "Requirements Registry":
            if not _user_can("can_view_registry"):
                st.warning("You do not have permission to access Requirements Registry.") # Patch 2
            elif can_view("Requirements Registry"):
                st.subheader("Requirements Registry")
                _ensure_reqlog_in_state()
                df = st.session_state.reqlog_df.copy()

                _sites = _user_allowed_sites()
                if "*" not in _sites and not _user_is_master_admin():
                    df = df[df["project_code"].isin(_sites)].copy()

                c1, c2, c3, c4 = st.columns(4)
                with c1: proj_pick = st.multiselect("Project", sorted(df["project_code"].dropna().unique()), default=[], key="reg-proj-pick")
                with c2: type_pick = st.multiselect("Type", sorted(df["request_type"].dropna().unique()), default=[], key="reg-type-pick")
                with c3: vendor_pick = st.multiselect("Vendor", sorted(df["vendor"].dropna().unique()), default=[], key="reg-vendor-pick")
                with c4: status_pick = st.multiselect("Status", sorted(df["status"].dropna().unique()), default=[], key="reg-status-pick")

                if proj_pick: df = df[df["project_code"].isin(proj_pick)]
                if type_pick: df = df[df["request_type"].isin(type_pick)]
                if vendor_pick: df = df[df["vendor"].isin(vendor_pick)]
                if status_pick: df = df[df["status"].isin(status_pick)]

                st.dataframe(df.sort_values("generated_at", ascending=False), use_container_width=True, hide_index=True)
                st.download_button("⬇️ Download Registry (CSV)", data=df.to_csv(index=False).encode("utf-8"),
                                  file_name="requirements_registry.csv", mime="text/csv", key="reg-dl")

                st.markdown("### View / Print a Raised Requirement")
                render_registry_view_print_controls(st, df, st.session_state.company_meta)

                if _user_is_master_admin() or _user_is_site_admin():
                    render_registry_admin_actions(st, reqlog_df=st.session_state.reqlog_df, items_df=items_f,
                        company_meta=st.session_state.company_meta,
                        save_cb=lambda dfu: (write_reqlog_df(dfu), setattr(st.session_state, "reqlog_df", dfu)))

                    st.markdown("### Approval Actions")
                    with st.expander("🔧 Password Admin", expanded=False):
                        em = st.text_input("User email", key="padm-email")
                        c1, c2 = st.columns(2)
                        with c1:
                            if st.button("Send reset link email", key="padm-reset"):
                                try:
                                    from db_adapter import start_password_reset
                                    ok, msg, token, exp = start_password_reset(em, ttl_minutes=30)
                                    if ok and token:
                                        base_url = st.secrets.get("app_base_url", "") or ""
                                        reset_link = f"{base_url}?reset_token={token}" if base_url else f"?reset_token={token}"
                                        html = f"""
                                        <div style="font-family:Arial,Helvetica,sans-serif;color:#222">
                                          <p>A password reset was requested by admin.</p>
                                          <p><a href="{reset_link}">Click here to reset your password</a></p>
                                          <p>This link expires at <b>{exp}</b> (UTC).</p>
                                        </div>
                                        """
                                        subject = "SJCPL — Password Reset"
                                        okm, emsg = send_email_via_smtp(em, subject, html, None, None)
                                        st.success("Reset email sent." if okm else f"Email send failed: {emsg}")
                                    else:
                                        st.error(msg)
                                except Exception as e:
                                    st.error(f"Error: {e}")
                        with c2:
                            newp = st.text_input("Set password (direct)", type="password", key="padm-setp")
                            if st.button("Set password now", key="padm-setp-btn"):
                                try:
                                    from db_adapter import set_user_password
                                    if not newp:
                                        st.error("Enter a new password.")
                                    else:
                                        ok = set_user_password(em, newp)
                                        st.success("Password set.") if ok else st.error("User not found.")
                                except Exception as e:
                                    st.error(f"Error: {e}")


                    # Focus on items needing approval by default
                    df_admin = df.copy()
                    # Filter for pending items only
                    df_admin = df_admin[df_admin["status"].astype(str).str.startswith("Pending")]
 
                    refs_to_act = st.multiselect(
                        "Select reference(s) to act on",
                        df_admin["ref"].astype(str).tolist(),
                        key="admin-approve-refs"
                    )
                    note = st.text_area("Note (will be recorded into status_detail)", "", key="admin-approve-note")

                    # Toggles: vendor OFF by default, requester ON by default
                    colA, colB, colC, colD = st.columns([1,1,1,2])
                    with colA:
                        do_approve = st.button("✅ Approve", type="primary", key="admin-approve-btn")
                    with colB:
                        do_reject = st.button("⛔ Reject", key="admin-reject-btn")
                        st.session_state["selected_refs_for_vendor_send"] = refs_to_act
                        send_vendor_after_approve = st.checkbox("Email vendor with PDF", value=True, key="admin-send-vendor")
                    with colD:
                        send_requester_after_approve = st.checkbox("Email requester with PDF", value=True, key="admin-send-requester")
 
                    if (do_approve or do_reject) and not refs_to_act:
                        st.warning("Pick at least one reference.")
                    elif do_approve or do_reject:
                        new_status = "Approved" if do_approve else "Rejected"
                        try: # 1) Update DB
                            update_requirement_status(refs_to_act, new_status, st.session_state.user.get("email",""), status_detail=note or "") # Update status in DB
                            st.session_state.reqlog_df = read_reqlog_df() # Refresh the session state DataFrame
                            st.success(f"{new_status}: {len(refs_to_act)} reference(s) updated.") # Success message

                        except Exception as e:
                            st.error(f"Failed to update status: {e}")
                            st.stop() # Stop here to prevent further execution and allow rerun
 
                        # 2) Load the rows we just acted on (for emails/PDF)
                        try:
                            rows = read_requirements_by_refs(refs_to_act)
                        except Exception as e:
                            rows = []
                            st.error(f"Could not reload selected refs for emailing: {e}")

                        # 3) Build one combined PDF (reuse for vendor & requester)
                        pdf_bytes = b""
                        if rows:
                            try:
                                pdf_bytes = build_requirement_pdf_from_rows(rows, st.session_state.company_meta)
                            except Exception as e:
                                pdf_bytes = b"" # Ensure pdf_bytes is empty on failure
                                st.error(f"PDF build failed: {e}")
 
                        # 4) Optionally email vendors (group by vendor)
                        if do_approve and send_vendor_after_approve and rows and pdf_bytes: # Only send if explicitly checked
                            from collections import defaultdict
                            by_vendor = defaultdict(list)
                            for r in rows:
                                by_vendor[str(r.get("vendor",""))].append(r) # Group by vendor
 
                            sent_ok, sent_err = 0, []
                            for vendor_key, bucket in by_vendor.items():
                                v_email = None
                                try:
                                    v_email = get_vendor_email(vendor_key)
                                    if not v_email:
                                        st.warning(f"No vendor email configured for: {vendor_key}. (Admin → Vendor Contacts)")
                                        continue # Skip if no email found
 
                                    subject = build_vendor_email_subject(bucket[0])
                                    body_rows = "".join(
                                        f"<tr><td style='padding:4px 8px'>{r.get('ref','')}</td>"
                                        f"<td style='padding:4px 8px'>{r.get('description','')}</td>"
                                        f"<td style='padding:4px 8px'>{r.get('qty','')} {r.get('uom','')}</td></tr>"
                                        for r in bucket
                                    )
                                    html_body = f"""
                                    <div style="font-family:Arial,Helvetica,sans-serif;color:#222">
                                      <p>The following request(s) have been <b>Approved</b>:</p>
                                      <table style="border-collapse:collapse;font-size:13px"> 
                                        <thead><tr style="background:#f0f0f0"><th style="padding:4px 8px;text-align:left">Ref</th><th style="padding:4px 8px;text-align:left">Item</th><th style="padding:4px 8px;text-align:left">Qty</th></tr></thead>
                                        <tbody>{body_rows}</tbody>
                                      </table>
                                      <p>Attached: approved request PDF.</p>
                                    </div>
                                    """
                                    attach_name = f"Approved_{bucket[0].get('project_code','')}.pdf"
 
                                    ok_mail, msg_mail = send_email_via_smtp(v_email, subject, html_body, pdf_bytes, attach_name)
                                    try:
                                        log_requirement_email(bucket[0].get("ref",""), vendor_key, v_email, subject, ok_mail, (None if ok_mail else msg_mail))
                                    except Exception: # Best-effort logging
                                        pass
 
                                    if ok_mail: sent_ok += 1 # Count successful sends
                                    else: sent_err.append(f"{vendor_key} → {v_email}: {msg_mail}")
 
                                except Exception as e:
                                    sent_err.append(f"{vendor_key} → {v_email or '-'}: {e}")
                                    continue
 
                            if sent_ok:
                                st.success(f"Emailed vendor(s) for {sent_ok} group(s).")
                            if sent_err:
                                st.error("Some vendor emails failed: " + "; ".join(sent_err)) # Report all errors
 
                        # 5) Optionally email requesters (group by generated_by_email)
                        if do_approve and send_requester_after_approve and rows and pdf_bytes:
                            from collections import defaultdict
                            by_requester = defaultdict(list)
                            for r in rows:
                                remail = (r.get("generated_by_email") or "").strip()
                                if remail: # Group by requester email
                                    by_requester[remail].append(r)
 
                            if not by_requester:
                                st.warning("No requester email found on the selected refs.")
                            else:
                                approver_name = st.session_state.get("user",{}).get("name") or st.session_state.get("user",{}).get("email") or "Approver"
                                sent_ok_r, sent_err_r = 0, []
                                for remail, bucket in by_requester.items():
                                    subject = f"[SJCPL] Your request was Approved — {bucket[0].get('project_code','')} — {len(bucket)} item(s)"
                                    body_rows = "".join(
                                        f"<tr><td style='padding:4px 8px'>{r.get('ref','')}</td>"
                                        f"<td style='padding:4px 8px'>{r.get('description','')}</td>"
                                        f"<td style='padding:4px 8px'>{r.get('qty','')} {r.get('uom','')}</td></tr>"
                                        for r in bucket
                                    )
                                    html_body = f"""
                                    <div style="font-family:Arial,Helvetica,sans-serif;color:#222">
                                      <p><b>Your request has been approved</b> by {approver_name}.</p>
                                      <table style="border-collapse:collapse;font-size:13px">
                                        <thead><tr style="background:#f0f0f0">
                                          <th style="padding:4px 8px;text-align:left">Ref</th>
                                          <th style="padding:4px 8px;text-align:left">Item</th>
                                          <th style="padding:4px 8px;text-align:left">Qty</th>
                                        </tr></thead>
                                        <tbody>{body_rows}</tbody>
                                      </table>
                                      <p>Attached: approved request PDF.</p>
                                    </div>
                                    """
                                    attach_name = f"Approved_{bucket[0].get('project_code','')}.pdf"
                                    ok_mail, msg_mail = send_email_via_smtp(remail, subject, html_body, pdf_bytes, attach_name)
 
                                    try:
                                        log_requirement_email(bucket[0].get("ref",""), bucket[0].get("vendor",""), remail, subject, ok_mail, (None if ok_mail else msg_mail)) # Log for requester
                                    except Exception: # Best-effort logging
                                        pass
 
                                    if ok_mail: sent_ok_r += 1 # Count successful sends
                                    else: sent_err_r.append(f"{remail}: {msg_mail}")
 
                                if sent_ok_r:
                                    st.success(f"Emailed requester(s) for {sent_ok_r} group(s).")
                                if sent_err_r:
                                    st.error("Some requester emails failed: " + "; ".join(sent_err_r))
                        # 6) Finally, refresh the grid
                        st.rerun()

                # NEW: Separate expander for Send Email to Vendor (only for Approved / Auto Approved)
                with st.expander("📧 Send Email to Vendor (Approved items only)", expanded=False):
                    refs_all = df[df["status"].isin(["Approved","Auto Approved"])]["ref"].astype(str).tolist()
                    refs_pick = st.multiselect("Select ref(s)", refs_all, key="reg-email-refs")
                    if st.button("Send vendor email", key="reg-email-btn"):
                        _send_vendor_emails_for_refs(refs_pick)
                        st.rerun()
        elif tab_label == "Admin":
            if can_view("Admin") and _user_is_master_admin():
                st.subheader("Admin — Users & Access")
                _ensure_acl_in_state()
                st.dataframe(st.session_state.acl_df, use_container_width=True, hide_index=True)

                with st.expander("➕ Add / Update User", expanded=False):
                    available_sites = sorted(items_df["Project_Key"].dropna().unique().tolist()) if not items_df.empty else []
                    site_choices = ["*"] + available_sites
                    tab_choices = [t for t in all_tab_names if t != "Admin"] + ["*"]

                    a1, a2 = st.columns(2)
                    email = a1.text_input("Email", key="admin-email")
                    name = a1.text_input("Name", key="admin-name")
                    role = a1.selectbox("Role", ["master_admin", "site_admin", "user"], key="admin-role")

                    fast_col1, fast_col2 = st.columns([1,1])
                    with fast_col1:
                        sites_quick = st.selectbox("Quick pick sites", ["Custom", "All Sites", "None", "Matches keyword"], index=0, key="admin-sites-quick")
                    with fast_col2:
                        sites_keyword = st.text_input("Keyword (for Matches)", "", key="admin-sites-keyword")

                    sites_multi = a2.multiselect("Sites (choose one or more, or * for all)", site_choices, default=["*"] if "*" in site_choices else [], key="admin-sites")
                    tabs_multi  = a2.multiselect("Tabs (choose one or more, or * for all)", tab_choices, default=["*"], key="admin-tabs")

                    can_raise = st.checkbox("Can raise requests (otherwise view-only)", value=True, key="admin-can-raise")
                    can_view_registry = st.checkbox("Can view Requirements Registry", value=True, key="admin-can-view-reg")
                    can_export = st.checkbox("Can use Export tab", value=True, key="admin-can-export")
                    can_email_drafts = st.checkbox("Can use Email Drafts tab", value=True, key="admin-can-email")

                    pwd   = st.text_input("Password (stored as SHA256 hash)", type="password", key="admin-pwd")
                    if st.button("Save User", type="primary", key="admin-save-user"):
                        if not email:
                            st.error("Email required.")
                        else:
                            ph = _sha256_hex(pwd) if pwd else None
                            dfu = st.session_state.acl_df.copy()

                            if sites_quick == "All Sites":
                                sites_val = "*"
                            elif sites_quick == "None":
                                sites_val = ""
                            elif sites_quick == "Matches keyword":
                                if sites_keyword.strip():
                                    matches = [s for s in available_sites if sites_keyword.strip().lower() in str(s).lower()]
                                    sites_val = "|".join(matches)
                                else:
                                    sites_val = "|".join(sites_multi)
                            else:
                                sites_val = "*" if "*" in sites_multi else "|".join(sites_multi)

                            tabs_val = "*" if "*" in tabs_multi else "|".join(tabs_multi)

                            if (dfu["email"] == email).any():
                                if name:
                                    dfu.loc[dfu["email"] == email, "name"] = name
                                dfu.loc[dfu["email"] == email, "role"]  = role
                                dfu.loc[dfu["email"] == email, "sites"] = sites_val
                                dfu.loc[dfu["email"] == email, "tabs"]  = tabs_val
                                dfu.loc[dfu["email"] == email, "can_raise"] = bool(can_raise)
                                dfu.loc[dfu["email"] == email, "can_view_registry"] = bool(can_view_registry)
                                dfu.loc[dfu["email"] == email, "can_export"] = bool(can_export)
                                dfu.loc[dfu["email"] == email, "can_email_drafts"] = bool(can_email_drafts)
                                if ph:
                                    dfu.loc[dfu["email"] == email, "password_hash"] = ph
                            else:
                                if not ph:
                                    st.error("Password required for new user.")
                                    st.stop()
                                new_user_data = {
                                    "email": email, "name": name, "role": role, "sites": sites_val,
                                    "tabs": tabs_val, "can_raise": bool(can_raise),
									"can_view_registry": bool(can_view_registry), "can_export": bool(can_export),
                                    "can_email_drafts": bool(can_email_drafts),
                                    "password_hash": ph
                                }
                                dfu = pd.concat([dfu, pd.DataFrame([new_user_data])], ignore_index=True)
                            
                            st.session_state.acl_df = dfu
                            write_acl_df(dfu)
                            st.success("User saved.")
                
                # Admin UI: master-admin–only Vendor Contacts manager
                with st.expander("📧 Vendor Contacts (DB-only, master admin)"):
                    try:
                        vdf = read_vendor_contacts()
                    except Exception as e:
                        vdf = pd.DataFrame(columns=["vendor","email"])
                        st.error(f"Failed to read vendor contacts: {e}")
                    st.caption("Map Subcontractor_Key → Vendor email. Only stored in the database.")
                    st.dataframe(vdf, use_container_width=True, hide_index=True)

                    with st.form("vendor-email-upsert"):
                        nv = st.text_input("Vendor (Subcontractor_Key)")
                        ne = st.text_input("Vendor Email")
                        submit_vendor = st.form_submit_button("Save / Update", type="primary")
                    if submit_vendor:
                        if not nv or not ne:
                            st.error("Vendor and email are required.")
                        else:
                            try:
                                upsert_vendor_contact(nv.strip(), ne.strip(), by_email=st.session_state.user.get("email"))
                                st.success("Saved/updated.")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Save failed: {e}")
        elif tab_label == "Raise Requirement":
            cleaned_for_save = _clean_text_for_line(items_df, proj_pick, vend_pick, wo_pick, line_pick) if line_pick else (st.session_state.get("rr-desc","") or "")
            desc_final = cleaned_for_save.strip()
            if st.button("↻ Use selected line text", key="rr-sync-desc"):
                cleaned = _clean_text_for_line(items_df, proj_pick, vend_pick, wo_pick, line_pick) if line_pick else ""
                st.session_state["rr-desc"] = cleaned
                st.session_state["rr-line_item"] = cleaned
                st.session_state.rr_state["touched"] = False
                st.rerun()
        elif tab_label == "Raise Requirement":
            cleaned_for_save = _clean_text_for_line(items_df, proj_pick, vend_pick, wo_pick, line_pick) if line_pick else (st.session_state.get("rr-desc","") or "")
            desc_final = cleaned_for_save.strip()
            line_item_final = cleaned_for_save.strip() # keep in sync

            if can_view("Raise Requirement"):
                st.subheader("Raise New Requirement")
                st.caption("Fill out the details below to raise a new requirement.")

                # --- Project/Vendor/WO/Line selectors ---
                proj_pick = st.selectbox("Project", projects, key="rr-proj")
                subs_for_proj = sorted(items_df[items_df["Project_Key"] == proj_pick]["Subcontractor_Key"].dropna().unique())
                vend_pick = st.selectbox("Vendor", subs_for_proj, key="rr-vendor")
                wos_for_vend = sorted(items_df[(items_df["Project_Key"] == proj_pick) & (items_df["Subcontractor_Key"] == vend_pick)]["WO_Key"].dropna().unique())
                wo_pick = st.selectbox("Work Order", wos_for_vend, key="rr-wo")

                line_keys_for_wo = sorted(
                    items_df.loc[
                        (items_df["Project_Key"] == proj_pick) &
                        (items_df["Subcontractor_Key"] == vend_pick) &
                        (items_df["WO_Key"] == wo_pick),
                        "Line_Key"
                    ].astype(str).unique()
                )
                line_pick = st.selectbox("Select Line", ["NEW"] + line_keys_for_wo, key="rr-line")

                # --- init state buckets once ---
                if "rr_state" not in st.session_state:
                    st.session_state.rr_state = {"touched": False, "last_key": ""}

                # Compute a selection fingerprint
                sel_key = f"{proj_pick}|{vend_pick}|{wo_pick}|{line_pick}"

                # If selection changed, (re)populate description from line text and clear "touched"
                if st.session_state.rr_state.get("last_key") != sel_key:
                    cleaned = _clean_text_for_line(items_df, proj_pick, vend_pick, wo_pick, line_pick) if line_pick != "NEW" else ""
                    st.session_state["rr-desc"] = cleaned                   # <- sets the textarea content
                    st.session_state["rr-line_item"] = cleaned              # keep line_item == description
                    st.session_state.rr_state.update({"touched": False, "last_key": sel_key})

                # Small callback to mark that user edited description
                def _mark_desc_touched():
                    st.session_state.rr_state["touched"] = True
                st.text_area("Description (auto = line text; you can edit)", key="rr-desc", on_change=_mark_desc_touched)

                # UOM / Stage (kept from DF but editable)
                if "rr-uom" not in st.session_state or st.session_state.rr_state["touched"] is False:
                    # (re)prefill on selection change; keep user edits after touched=True
                    prefill_data = _prefill_from_line(items_df, proj_pick, vend_pick, wo_pick, line_pick) if line_pick != "NEW" else {}
                    st.session_state["rr-uom"] = prefill_data.get("uom", "")
                    st.session_state["rr-stage"] = prefill_data.get("stage", "")

                st.text_input("UOM", key="rr-uom")
                st.text_input("Stage", key="rr-stage")
                qty_val = st.number_input("Quantity", min_value=0.0, step=1.0, key="rr-qty")
                remarks_v = st.text_input("Remarks (optional)", key="rr-remarks")

                with st.expander("✅ Approval Recipients (master admin)"):
                    st.caption("Recipients here will receive emails when a request is Pending Admin Approval.")
                    # Load current recipients
                    try:
                        arec = read_approval_recipients()
                    except Exception as e:
                        arec = pd.DataFrame(columns=["id","project_code","vendor_key","request_type","email"])
                        st.error(f"Failed to read approval recipients: {e}")

                    # Show table
                    st.dataframe(
                        arec if not arec.empty else pd.DataFrame(columns=["id","project_code","vendor_key","request_type","email"]),
                        use_container_width=True, hide_index=True
                    )

                    # Add / Update (in a form to avoid mid-typing reruns)
                    with st.form("appr-edit-form", clear_on_submit=False):
                        st.markdown("**Add / Update recipient**")
                        c1, c2 = st.columns(2)
                        with c1:
                            rec_id = st.number_input("Record ID (0 = create new)", min_value=0, value=0, step=1, key="appr-id")
                            pc = st.text_input("Project Code (optional)", key="appr-pc")
                            vk = st.text_input("Vendor Key (Subcontractor_Key, optional)", key="appr-vk")
                        with c2:
                            rt = st.text_input("Request Type (optional, e.g. QCTest)", key="appr-rt")
                            em = st.text_input("Approver Email (required)", key="appr-email")
                            save_btn = st.form_submit_button("Save Recipient", type="primary")
                        if save_btn:
                            if not em.strip():
                                st.error("Email is required.")
                            else:
                                try:
                                    upsert_approval_recipient(
                                        pc.strip() or None, vk.strip() or None, rt.strip() or None,
                                        em.strip(), by_email=st.session_state.get("user",{}).get("email"),
                                        rec_id=(rec_id or None)
                                    )
                                    st.success("Saved.")
                                    st.rerun()
                                except Exception as e:
                                    st.error(f"Save failed: {e}")

                    # Delete (separate form)
                    with st.form("appr-del-form"):
                        del_id = st.number_input("Delete by ID", min_value=0, value=0, step=1, key="appr-del-id")
                        del_btn = st.form_submit_button("Delete Recipient")
                        if del_btn:
                            try:
                                if del_id > 0:
                                    delete_approval_recipient(int(del_id))
                                    st.success("Deleted.")
                                    st.rerun()
                                else:
                                    st.warning("Enter a valid ID (> 0).")
                            except Exception as e:
                                st.error(f"Delete failed: {e}")

                    st.markdown("""
                    <div style="font-size:12px;color:#555;line-height:1.5">
                        <b>Scoping rules (most specific → least):</b><br/>
                        (project_code, vendor_key, request_type) → (project_code, vendor_key, NULL) →
                        (project_code, NULL, request_type) → (NULL, vendor_key, request_type) →
                        (project_code, NULL, NULL) → (NULL, vendor_key, NULL) →
                        (NULL, NULL, request_type) → (NULL, NULL, NULL).
                    </div>
                    """, unsafe_allow_html=True)
                # Add SMTP Diagnostics
                def smtp_connectivity_check():
                    ok, cfg = _smtp_config_ok()
                    if not ok:
                        st.error("SMTP not configured. Please fill .streamlit/secrets.toml [smtp].")
                        return
                    st.write(f"Host: {cfg['host']}  Port: {cfg['port']}  From: {cfg['from_email']}")
                    try:
                        # Try STARTTLS on configured port
                        import smtplib, ssl, socket
                        context = ssl.create_default_context()
                        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=cfg["timeout"]) as s:
                            s.ehlo()
                            s.starttls(context=context)
                            s.ehlo()
                        st.success(f"STARTTLS connection OK on {cfg['host']}:{cfg['port']}")
                    except Exception as e:
                        st.warning(f"STARTTLS check failed on {cfg['host']}:{cfg['port']} → {e}")
                with st.expander("📮 SMTP Diagnostics"):
                    if st.button("Run SMTP connectivity check"):
                        smtp_connectivity_check()
                    st.caption("Tip: If both checks fail, your host likely blocks SMTP egress. Use an email API (SendG")




                with st.expander("🗑️ Remove User", expanded=False):
                    emails = sorted(st.session_state.acl_df["email"].tolist())
                    if emails:
                        rm = st.selectbox("Select user to remove", emails, key="admin-remove-email")
                        if st.button("Remove", type="secondary", key="admin-remove-btn"):
                            st.session_state.acl_df = st.session_state.acl_df[st.session_state.acl_df["email"] != rm].reset_index(drop=True)
                            write_acl_df(st.session_state.acl_df)
                            st.success("User removed.")

                st.download_button("⬇️ Download ACL (CSV)", data=st.session_state.acl_df.to_csv(index=False).encode("utf-8"),
                                  file_name="acl_users.csv", mime="text/csv", key="acl-dl")

                st.subheader("Manage Enabled Tabs")
                enabled_sel = st.multiselect(
                    "Select enabled tabs", all_tab_names,
                    default=st.session_state.enabled_tabs,
                    key="admin-enabled-sel"
                )
                if st.button("Save Enabled Tabs", key="admin-save-enabled"):
                    st.session_state.enabled_tabs = enabled_sel
                    _save_enabled_tabs(enabled_sel)
                    st.success("Enabled tabs updated.")
                    st.rerun()


st.caption("© SJCPL-Test Request and Approvals — V1")