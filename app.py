#!/usr/bin/env python3
"""
faxweb — minimal LAN web front-end for sending faxes through a CUPS Epson fax queue.

Flow: browser form -> upload PDF + fax number -> `epfax2 -P <queue> -o fax-number=<n> file`
-> report the CUPS job + status. Shared-password gated, meant for a trusted LAN.

Config is entirely via environment variables (see README.md). Single file on purpose:
copy it (plus requirements) to the homeserver and run under systemd.
"""

import os
import re
import io
import json
import time
import hmac
import secrets
import subprocess
from pathlib import Path
from functools import wraps

from flask import (
    Flask, request, session, redirect, url_for,
    render_template_string, flash, abort, Response,
)

# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
def _bool(v: str) -> bool:
    return str(v).strip().lower() in {"1", "true", "yes", "on"}

QUEUE       = os.environ.get("FAX_QUEUE", "EPSON_FAX2")
EPFAX2      = os.environ.get("FAX_EPFAX2_BIN", "epfax2")
PASSWORD    = os.environ.get("FAX_PASSWORD", "")
DATA_DIR    = Path(os.environ.get("FAX_DATA_DIR", Path(__file__).parent / "data"))
MAX_MB      = int(os.environ.get("FAX_MAX_MB", "20"))
DRY_RUN     = _bool(os.environ.get("FAX_DRY_RUN", "0"))
PHONE_MIN   = int(os.environ.get("FAX_PHONE_MIN_DIGITS", "5"))
PHONE_MAX   = int(os.environ.get("FAX_PHONE_MAX_DIGITS", "15"))
ALLOWED_PAGESIZES = ("A4", "Letter", "Legal")

# International dialing prefix used when dialing a non-NANP number from this
# fax line. NANP lines (US/Canada) use "011"; override for lines elsewhere.
INTL_PREFIX = os.environ.get("FAX_INTL_PREFIX", "011")
DEFAULT_CC  = os.environ.get("FAX_DEFAULT_CC", "1")

# Country calling codes for the dropdown (submitted value = calling code digits).
COUNTRIES = [
    {"iso": "US", "name": "United States", "cc": "1",  "flag": "🇺🇸"},
    {"iso": "CA", "name": "Canada",        "cc": "1",  "flag": "🇨🇦"},
    {"iso": "MX", "name": "Mexico",        "cc": "52", "flag": "🇲🇽"},
    {"iso": "GB", "name": "United Kingdom","cc": "44", "flag": "🇬🇧"},
    {"iso": "IE", "name": "Ireland",       "cc": "353","flag": "🇮🇪"},
    {"iso": "FR", "name": "France",        "cc": "33", "flag": "🇫🇷"},
    {"iso": "DE", "name": "Germany",       "cc": "49", "flag": "🇩🇪"},
    {"iso": "ES", "name": "Spain",         "cc": "34", "flag": "🇪🇸"},
    {"iso": "IT", "name": "Italy",         "cc": "39", "flag": "🇮🇹"},
    {"iso": "NL", "name": "Netherlands",   "cc": "31", "flag": "🇳🇱"},
    {"iso": "CH", "name": "Switzerland",   "cc": "41", "flag": "🇨🇭"},
    {"iso": "SE", "name": "Sweden",        "cc": "46", "flag": "🇸🇪"},
    {"iso": "AU", "name": "Australia",     "cc": "61", "flag": "🇦🇺"},
    {"iso": "NZ", "name": "New Zealand",   "cc": "64", "flag": "🇳🇿"},
    {"iso": "JP", "name": "Japan",         "cc": "81", "flag": "🇯🇵"},
    {"iso": "KR", "name": "South Korea",   "cc": "82", "flag": "🇰🇷"},
    {"iso": "CN", "name": "China",         "cc": "86", "flag": "🇨🇳"},
    {"iso": "HK", "name": "Hong Kong",     "cc": "852","flag": "🇭🇰"},
    {"iso": "IN", "name": "India",         "cc": "91", "flag": "🇮🇳"},
    {"iso": "SG", "name": "Singapore",     "cc": "65", "flag": "🇸🇬"},
    {"iso": "BR", "name": "Brazil",        "cc": "55", "flag": "🇧🇷"},
    {"iso": "AR", "name": "Argentina",     "cc": "54", "flag": "🇦🇷"},
    {"iso": "ZA", "name": "South Africa",  "cc": "27", "flag": "🇿🇦"},
    {"iso": "IL", "name": "Israel",        "cc": "972","flag": "🇮🇱"},
    {"iso": "AE", "name": "UAE",           "cc": "971","flag": "🇦🇪"},
]

DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR = DATA_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
JOBS_LOG = DATA_DIR / "jobs.jsonl"

if not PASSWORD:
    raise SystemExit(
        "FAX_PASSWORD is not set. Refusing to start without a shared password.\n"
        "Set it, e.g.:  FAX_PASSWORD='something-strong' python3 app.py"
    )

# Persist the Flask session-signing key so sessions survive restarts.
_secret_file = DATA_DIR / "secret_key"
if os.environ.get("FAX_SECRET_KEY"):
    SECRET_KEY = os.environ["FAX_SECRET_KEY"].encode()
elif _secret_file.exists():
    SECRET_KEY = _secret_file.read_bytes()
else:
    SECRET_KEY = secrets.token_bytes(32)
    _secret_file.write_bytes(SECRET_KEY)
    _secret_file.chmod(0o600)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    MAX_CONTENT_LENGTH=MAX_MB * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 8,  # 8h
)

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def logged_in() -> bool:
    return session.get("auth") is True

def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **k):
        if not logged_in():
            return redirect(url_for("login_get", next=request.path))
        return fn(*a, **k)
    return wrapper

def csrf_token() -> str:
    tok = session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(24)
        session["csrf"] = tok
    return tok

def check_csrf():
    sent = request.form.get("csrf", "")
    good = session.get("csrf", "")
    if not good or not hmac.compare_digest(sent, good):
        abort(400, "Bad or missing CSRF token — reload the page and try again.")

def format_fax_number(cc: str, raw: str):
    """Validate and normalize a fax number for a given country calling code.

    Returns (display, dial): `display` is human-readable ("+1 972-555-0123" /
    "+44 2079460958"); `dial` is the exact digit string handed to epfax2 —
    domestic 10-digit for NANP (+1), otherwise INTL_PREFIX + cc + national.
    Returns (None, None) if the number fails validation for that country.
    """
    cc = re.sub(r"\D", "", cc or "")
    nat = re.sub(r"\D", "", raw or "")
    if not cc:
        return None, None
    if cc == "1":
        # NANP: NPA-NXX-XXXX. Area code (NPA) and exchange (NXX) start with 2-9.
        if len(nat) != 10 or nat[0] in "01" or nat[3] in "01":
            return None, None
        display = f"+1 {nat[:3]}-{nat[3:6]}-{nat[6:]}"
        dial = nat  # domestic dialing, matches the known-working CLI
    else:
        if not (PHONE_MIN <= len(nat) <= PHONE_MAX):
            return None, None
        display = f"+{cc} {nat}"
        dial = INTL_PREFIX + cc + nat
    return display, dial

def looks_like_pdf(head: bytes) -> bool:
    return head[:5] == b"%PDF-"

def record_job(entry: dict):
    entry["ts"] = int(time.time())
    with JOBS_LOG.open("a") as f:
        f.write(json.dumps(entry) + "\n")

def recent_jobs(limit: int = 25):
    if not JOBS_LOG.exists():
        return []
    lines = JOBS_LOG.read_text().splitlines()[-limit:]
    out = []
    for ln in reversed(lines):
        try:
            out.append(json.loads(ln))
        except ValueError:
            continue
    return out

def active_cups_jobs() -> dict:
    """Map 'EPSON_FAX2-<n>' -> short status string for jobs still in the queue."""
    try:
        r = subprocess.run(["lpstat", "-o", QUEUE], capture_output=True,
                           text=True, timeout=10)
    except Exception:
        return {}
    status = {}
    for line in r.stdout.splitlines():
        parts = line.split()
        if parts:
            status[parts[0]] = "in queue"
    return status

_JOBID_RE = re.compile(r"request id is (\S+)")

def send_fax(pdf_path: Path, number: str, pagesize: str):
    """Run epfax2. Return (ok, job_id_or_None, message)."""
    if DRY_RUN:
        time.sleep(0.3)
        fake = f"DRYRUN-{int(time.time())}"
        return True, fake, f"[dry run] would run: {EPFAX2} -P {QUEUE} -o fax-number={number} …"

    cmd = [EPFAX2, "-P", QUEUE, "-o", f"fax-number={number}"]
    if pagesize in ALLOWED_PAGESIZES:
        cmd += ["-o", f"PageSize={pagesize}"]
    cmd.append(str(pdf_path))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return False, None, "epfax2 timed out after 180s."
    except FileNotFoundError:
        return False, None, f"'{EPFAX2}' not found — is the Epson fax driver installed on this host?"

    out = (r.stdout or "") + (r.stderr or "")
    m = _JOBID_RE.search(out)
    job_id = m.group(1) if m else None
    if r.returncode == 0:
        return True, job_id, out.strip() or "Submitted."
    return False, job_id, (out.strip() or f"epfax2 exited {r.returncode}.")

# --------------------------------------------------------------------------- #
# Templates (inline to keep this a single portable file)
# --------------------------------------------------------------------------- #
FONTS = ("https://fonts.googleapis.com/css2?"
         "family=Fraunces:ital,opsz,wght@0,9..144,400;0,9..144,500;0,9..144,600;"
         "1,9..144,400&family=Hanken+Grotesk:wght@400;500;600;700&"
         "family=IBM+Plex+Mono:wght@400;500&display=swap")

# Fax-machine favicon (inline SVG, served by the /favicon route — works offline).
FAVICON_SVG = (
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'>"
    "<rect width='32' height='32' rx='7' fill='#d13c22'/>"
    "<rect x='10' y='5.3' width='12' height='7.6' rx='1' fill='#fff'/>"          # feeding page
    "<rect x='12' y='7.9' width='8' height='1.3' rx='.65' fill='#d13c22'/>"
    "<rect x='12' y='10.2' width='6' height='1.3' rx='.65' fill='#d13c22'/>"
    "<rect x='6.4' y='12.4' width='19.2' height='13.3' rx='2.6' fill='#fff'/>"   # machine body
    "<rect x='9.3' y='15' width='13.4' height='1.9' rx='.95' fill='#d13c22'/>"   # paper slot
    "<circle cx='10.4' cy='20.2' r='1.45' fill='#d13c22'/>"                      # buttons
    "<circle cx='14.4' cy='20.2' r='1.45' fill='#d13c22'/>"
    "<rect x='17.6' y='18.7' width='5' height='4.8' rx='1' fill='#d13c22'/>"     # display
    "</svg>"
)

BASE = """
<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width, initial-scale=1">
<title>{{ title or 'faxweb' }}</title>
<link rel=icon type="image/svg+xml" href="{{ url_for('favicon') }}">
<link rel=preconnect href="https://fonts.googleapis.com">
<link rel=preconnect href="https://fonts.gstatic.com" crossorigin>
<link href="{{ fonts }}" rel=stylesheet>
<style>
  :root{
    --paper:#f3efe5; --panel:#fbf9f3; --panel-2:#efe9db;
    --ink:#1a1611; --muted:#7a7264; --faint:#a79e8d;
    --line:#ddd5c4; --line-strong:#cabfa8;
    --accent:#d13c22; --accent-ink:#fff; --accent-dim:#b3331b;
    --ok:#2f7150; --ok-bg:#e2ece2; --err:#b23320; --err-bg:#f6e2dc;
    --shadow: 0 1px 2px rgba(50,38,22,.05), 0 22px 44px -26px rgba(50,38,22,.28);
    --r:16px; --r-sm:10px;
  }
  *{box-sizing:border-box;}
  html{-webkit-text-size-adjust:100%;}
  body{
    margin:0; min-height:100vh; color:var(--ink);
    font-family:"Hanken Grotesk", ui-sans-serif, system-ui, sans-serif;
    font-size:15px; line-height:1.55; letter-spacing:-0.005em;
    background:
      radial-gradient(1200px 700px at 82% -8%, #fbf8f0 0%, rgba(251,248,240,0) 60%),
      radial-gradient(900px 600px at -6% 108%, #efe7d6 0%, rgba(239,231,214,0) 55%),
      var(--paper);
  }
  /* film grain */
  body::before{
    content:""; position:fixed; inset:0; z-index:0; pointer-events:none; opacity:.05;
    background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='140' height='140'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.8' numOctaves='2' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");
  }
  .wrap{position:relative; z-index:1; max-width:1040px; margin:0 auto; padding:34px 22px 72px;}
  a{color:var(--accent); text-decoration:none;} a:hover{text-decoration:underline;}

  .mono{font-family:"IBM Plex Mono", ui-monospace, monospace;}
  .eyebrow{font-family:"IBM Plex Mono", monospace; font-size:11px; font-weight:500;
    letter-spacing:.18em; text-transform:uppercase; color:var(--faint);}
  h1,h2{font-family:"Fraunces", Georgia, serif; font-weight:500; letter-spacing:-0.01em;
    margin:0; line-height:1.08;}

  /* header */
  .masthead{display:flex; align-items:center; justify-content:space-between; gap:16px;
    margin-bottom:26px;}
  .brand{display:flex; align-items:center; gap:13px;}
  .mark{width:38px; height:38px; border-radius:11px; flex:none; display:grid; place-items:center;
    background:var(--accent); color:var(--accent-ink); box-shadow:var(--shadow);
    font-family:"Fraunces",serif; font-style:italic; font-weight:600; font-size:20px;}
  .brand h1{font-size:23px;} .brand .sub{color:var(--muted); font-size:12.5px; margin-top:1px;}
  .brand .sub b{color:var(--accent); font-weight:600;}

  .card{background:var(--panel); border:1px solid var(--line); border-radius:var(--r);
    box-shadow:var(--shadow);}
  .pad{padding:24px;}

  /* two-panel compose grid */
  .grid{display:grid; grid-template-columns:1fr 1.05fr; gap:20px; align-items:stretch;}
  @media(max-width:820px){ .grid{grid-template-columns:1fr;} }

  label.field{display:block; margin:0 0 18px;}
  label.field:last-of-type{margin-bottom:0;}
  .field > span{display:block; margin-bottom:7px;}
  input[type=tel],input[type=password],select{
    width:100%; padding:12px 13px; font:inherit; color:var(--ink);
    background:var(--panel-2); border:1px solid var(--line-strong); border-radius:var(--r-sm);
    transition:border-color .15s, box-shadow .15s, background .15s;}
  input[type=tel]{font-family:"IBM Plex Mono",monospace; letter-spacing:.03em;}
  input:focus,select:focus{outline:none; border-color:var(--accent);
    box-shadow:0 0 0 3px rgba(209,60,34,.16); background:var(--panel);}
  input.bad{border-color:var(--err); box-shadow:0 0 0 3px rgba(178,51,32,.14);}
  .fieldnote{display:block; margin-top:7px; font-size:12px; font-family:"IBM Plex Mono",monospace;
    min-height:1em; color:var(--muted);}
  .fieldnote.ok{color:var(--ok);} .fieldnote.bad{color:var(--err);}
  .telgroup{display:flex; gap:8px;}
  .telgroup .ccsel{flex:none; width:auto; padding-left:12px; padding-right:30px;
    font-family:"IBM Plex Mono",monospace; letter-spacing:0;}
  .telgroup input{flex:1; min-width:0;}
  .sendbtn{margin-top:24px;}
  select{appearance:none; cursor:pointer;
    background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' fill='none' stroke='%237a7264' stroke-width='1.6'%3E%3Cpath d='M2 4l4 4 4-4'/%3E%3C/svg%3E");
    background-repeat:no-repeat; background-position:right 13px center; padding-right:34px;}

  .btn{display:inline-flex; align-items:center; justify-content:center; gap:9px;
    padding:13px 20px; font:inherit; font-weight:600; letter-spacing:.01em; cursor:pointer;
    border:1px solid transparent; border-radius:var(--r-sm); transition:transform .08s, box-shadow .2s, background .2s, opacity .2s;}
  .btn:active{transform:translateY(1px);}
  .btn-primary{background:var(--accent); color:var(--accent-ink); width:100%;
    box-shadow:0 8px 20px -8px rgba(209,60,34,.6);}
  .btn-primary:hover{background:var(--accent-dim);}
  .btn-primary:disabled{opacity:.45; cursor:not-allowed; box-shadow:none;}
  .btn-ghost{background:transparent; color:var(--muted); border-color:var(--line-strong);
    padding:8px 14px; font-size:13px;}
  .btn-ghost:hover{color:var(--ink); border-color:var(--ink);}
  .hint{color:var(--muted); font-size:12.5px; margin:14px 0 0;}
  .hint b{color:var(--ink); font-weight:600;}

  /* dropzone */
  .drop{position:relative; border:1.5px dashed var(--line-strong); border-radius:var(--r-sm);
    background:var(--panel-2); padding:22px; text-align:center; cursor:pointer;
    transition:border-color .15s, background .15s;}
  .drop:hover,.drop.over{border-color:var(--accent); background:#f7efe9;}
  .drop.over{background:rgba(209,60,34,.06);}
  .drop.has{border-style:solid; text-align:left; padding:14px 16px;}
  .drop input[type=file]{position:absolute; inset:0; opacity:0; cursor:pointer;}
  .drop .ico{font-family:"Fraunces",serif; font-style:italic; font-size:26px; color:var(--accent);}
  .drop .big{font-weight:600; margin-top:6px;} .drop .sm{color:var(--muted); font-size:12.5px;}
  .filerow{display:flex; align-items:center; gap:12px;}
  .filerow .fi{width:34px; height:42px; flex:none; border-radius:5px; background:var(--accent);
    color:#fff; display:grid; place-items:center; font-size:9px; font-weight:600;
    font-family:"IBM Plex Mono",monospace; box-shadow:var(--shadow);}
  .filerow .meta{min-width:0; flex:1;}
  .filerow .fn{font-weight:600; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;}
  .filerow .fs{color:var(--muted); font-size:12px; font-family:"IBM Plex Mono",monospace;}
  .xbtn{flex:none; border:none; background:transparent; color:var(--faint); cursor:pointer;
    font-size:20px; line-height:1; padding:4px 6px; border-radius:6px;}
  .xbtn:hover{color:var(--accent); background:var(--panel-2);}

  /* preview panel */
  .preview{display:flex; flex-direction:column; overflow:hidden; padding:0;}
  .preview .bar{display:flex; align-items:center; justify-content:space-between; gap:10px;
    padding:14px 18px; border-bottom:1px solid var(--line);}
  .preview .doc{flex:1; min-height:430px; background:
    repeating-linear-gradient(45deg,#efe9db 0 10px,#ece5d5 10px 20px);}
  .preview iframe{width:100%; height:100%; min-height:430px; border:0; display:block; background:#fff;}
  .empty{flex:1; min-height:430px; display:grid; place-items:center; text-align:center; padding:30px;}
  .empty .ring{width:70px; height:70px; border-radius:50%; border:1.5px dashed var(--line-strong);
    display:grid; place-items:center; margin:0 auto 16px; color:var(--faint);
    font-family:"Fraunces",serif; font-style:italic; font-size:30px;}
  .empty p{color:var(--muted); margin:.2em 0;} .empty .t{color:var(--ink); font-weight:600;}

  /* recent */
  .recent{margin-top:20px;}
  .sec-head{display:flex; align-items:baseline; gap:12px; margin:0 0 12px; padding:0 4px;}
  .sec-head h2{font-size:17px;} .sec-head .eyebrow{margin-left:auto;}
  .rlist{list-style:none; margin:0; padding:0;}
  .rlist li{display:grid; grid-template-columns:auto 1fr auto; align-items:center; gap:14px;
    padding:14px 20px; border-bottom:1px solid var(--line);}
  .rlist li:last-child{border-bottom:0;}
  .rlist .when{font-family:"IBM Plex Mono",monospace; font-size:12px; color:var(--muted);
    white-space:nowrap;}
  .rlist .to{font-family:"IBM Plex Mono",monospace; font-weight:500; letter-spacing:.02em;}
  .rlist .file{color:var(--muted); font-size:12.5px; white-space:nowrap; overflow:hidden;
    text-overflow:ellipsis;}
  .rlist .jid{color:var(--faint); font-size:11px; font-family:"IBM Plex Mono",monospace;}
  .pill{font-family:"IBM Plex Mono",monospace; font-size:11px; font-weight:500;
    padding:4px 10px; border-radius:999px; white-space:nowrap; letter-spacing:.02em;}
  .pill.ok{background:var(--ok-bg); color:var(--ok);}
  .pill.bad{background:var(--err-bg); color:var(--err);}
  .empty-recent{color:var(--muted); padding:22px 20px; font-size:14px;}

  .banner{display:flex; align-items:center; gap:9px; margin:0 0 20px; padding:11px 16px;
    border-radius:var(--r-sm); background:var(--panel-2); border:1px solid var(--line-strong);
    font-size:12.5px; color:var(--muted);}
  .banner .dot{width:8px; height:8px; border-radius:50%; background:var(--accent); flex:none;
    box-shadow:0 0 0 4px rgba(209,60,34,.18);}

  /* toasts */
  .toasts{position:fixed; z-index:50; top:18px; right:18px; display:flex; flex-direction:column;
    gap:10px; max-width:min(360px,90vw);}
  .toast{display:flex; gap:11px; padding:13px 15px; border-radius:12px; box-shadow:var(--shadow);
    background:var(--panel); border:1px solid var(--line); animation:slidein .35s cubic-bezier(.2,.9,.3,1);}
  .toast .stripe{width:4px; border-radius:4px; flex:none;}
  .toast.ok .stripe{background:var(--ok);} .toast.err .stripe{background:var(--accent);}
  .toast .msg{font-size:13.5px; line-height:1.4;}
  @keyframes slidein{from{opacity:0; transform:translateX(16px);} to{opacity:1; transform:none;}}

  /* login */
  .login-wrap{min-height:100vh; display:grid; place-items:center; padding:24px;}
  .login-card{width:100%; max-width:380px;}
  .login-card .mark{margin:0 auto 18px;}
  .login-head{text-align:center; margin-bottom:22px;}
  .login-head h1{font-size:26px; margin-bottom:6px;}
  .login-head p{color:var(--muted); font-size:13px; margin:0;}

  .reveal{opacity:0; transform:translateY(10px); animation:rise .6s cubic-bezier(.2,.8,.2,1) forwards;}
  @keyframes rise{to{opacity:1; transform:none;}}
  @media(prefers-reduced-motion:reduce){.reveal{animation:none; opacity:1; transform:none;}}
</style></head><body>
<div class=toasts>
{% with msgs = get_flashed_messages(with_categories=true) %}
  {% for cat,msg in msgs %}
  <div class="toast {{cat}}"><div class=stripe></div><div class=msg>{{msg}}</div></div>
  {% endfor %}
{% endwith %}
</div>
{{ body|safe }}
<script>
  // auto-dismiss toasts
  document.querySelectorAll('.toast').forEach(function(t,i){
    setTimeout(function(){ t.style.transition='opacity .4s, transform .4s';
      t.style.opacity=0; t.style.transform='translateX(16px)';
      setTimeout(function(){t.remove();},400); }, 4200 + i*400);
  });
</script>
</body></html>
"""

LOGIN = """
<div class=login-wrap>
  <div class="card pad login-card reveal">
    <div class=mark>f</div>
    <div class=login-head>
      <div class=eyebrow>faxweb</div>
      <h1>Sign in</h1>
      <p>Enter the shared passphrase to send a fax.</p>
    </div>
    <form method=post action="{{ url_for('login') }}">
      <input type=hidden name=csrf value="{{ csrf }}">
      <input type=hidden name=next value="{{ next or '' }}">
      <label class=field for=pw><span class=eyebrow>Password</span>
        <input id=pw name=password type=password autofocus autocomplete=current-password
               placeholder="••••••••">
      </label>
      <button class="btn btn-primary" type=submit>Sign in →</button>
    </form>
    {% if dry %}<p class=hint style="text-align:center">◦ Dry-run mode — nothing is actually sent.</p>{% endif %}
  </div>
</div>
"""

INDEX = """
<div class=wrap>
  <div class="masthead reveal">
    <div class=brand>
      <div class=mark>f</div>
      <div>
        <h1>faxweb</h1>
        <div class=sub>PDF → <b>fax</b> · queue <span class=mono>{{ queue }}</span></div>
      </div>
    </div>
    <form method=post action="{{ url_for('logout') }}">
      <input type=hidden name=csrf value="{{ csrf }}">
      <button class="btn btn-ghost" type=submit>Sign out</button>
    </form>
  </div>

  {% if dry %}
  <div class="banner reveal" style="animation-delay:.04s">
    <span class=dot></span><span><b style="color:var(--ink)">Dry-run mode.</b>
    Submissions are logged and previewed, but no fax is actually sent.</span>
  </div>
  {% endif %}

  <form method=post action="{{ url_for('send') }}" enctype=multipart/form-data
        id=faxform data-maxmb="{{ max_mb }}" data-min="{{ phone_min }}" data-max="{{ phone_max }}">
    <input type=hidden name=csrf value="{{ csrf }}">
    <div class=grid>
      <!-- compose -->
      <div class="card pad reveal" style="animation-delay:.06s">
        <div class=eyebrow style="margin-bottom:16px">Compose</div>
        <label class=field for=number><span class=eyebrow>Fax number</span>
          <div class=telgroup>
            <select id=cc name=cc class=ccsel aria-label="Country calling code">
              {% for c in countries %}
              <option value="{{ c.cc }}" data-iso="{{ c.iso }}"
                {%- if c.iso == 'US' %} selected{% endif %}>{{ c.flag }} +{{ c.cc }}</option>
              {% endfor %}
            </select>
            <input id=number name=number type=tel inputmode=tel autocomplete=off
                   placeholder="972-555-0123" required aria-describedby=numHint>
          </div>
          <span class=fieldnote id=numHint></span>
        </label>
        <label class=field><span class=eyebrow>Document</span>
          <div class=drop id=drop>
            <input id=file name=file type=file accept="application/pdf,.pdf" required>
            <div id=dropEmpty>
              <div class=ico>↑</div>
              <div class=big>Drop a PDF or click to browse</div>
              <div class=sm>PDF only · up to {{ max_mb }} MB</div>
            </div>
            <div class=filerow id=fileRow style="display:none">
              <div class=fi>PDF</div>
              <div class=meta><div class=fn id=fileName></div><div class=fs id=fileSize></div></div>
              <button type=button class=xbtn id=fileClear title="Remove">×</button>
            </div>
          </div>
        </label>
        <label class=field for=pagesize><span class=eyebrow>Page size</span>
          <select id=pagesize name=pagesize>
            <option>Letter</option><option>A4</option><option>Legal</option>
          </select>
        </label>
        <button class="btn btn-primary sendbtn" type=submit id=sendBtn disabled>Send fax →</button>
        <p class=hint>Sends via <b>{{ queue }}</b>. Delivery isn’t always printed —
        check the fax machine’s status/log to confirm receipt.</p>
      </div>

      <!-- preview -->
      <div class="card preview reveal" style="animation-delay:.12s">
        <div class=bar>
          <span class=eyebrow>Preview</span>
          <span class=eyebrow id=previewTag style="color:var(--faint)">no document</span>
        </div>
        <div class=empty id=previewEmpty>
          <div>
            <div class=ring>◈</div>
            <p class=t>No document selected</p>
            <p>Choose a PDF and it’ll render right here.</p>
          </div>
        </div>
        <div class=doc id=previewDoc style="display:none">
          <iframe id=previewFrame title="PDF preview"></iframe>
        </div>
      </div>
    </div>
  </form>

  <div class="card recent reveal" style="animation-delay:.18s; margin-top:20px">
    <div class=bar style="display:flex; align-items:center; justify-content:space-between; padding:16px 20px; border-bottom:1px solid var(--line)">
      <h2 style="font-size:17px">Recent faxes</h2>
      <span class=eyebrow>last {{ jobs|length }}</span>
    </div>
    {% if jobs %}
    <ul class=rlist>
      {% for j in jobs %}
      <li>
        <span class=when>{{ j.when }}</span>
        <span style="min-width:0">
          <span class=to>{{ j.number }}</span>
          <span class=file> · {{ j.filename }}</span>
          {% if j.job_id %}<span class=jid> · {{ j.job_id }}</span>{% endif %}
        </span>
        {% if j.ok %}<span class="pill ok">{{ j.live or 'submitted' }}</span>
        {% else %}<span class="pill bad">failed</span>{% endif %}
      </li>
      {% endfor %}
    </ul>
    {% else %}
    <div class=empty-recent>No faxes sent yet — your history will appear here.</div>
    {% endif %}
  </div>
</div>

<script>
(function(){
  var form=document.getElementById('faxform');
  var maxBytes=parseInt(form.dataset.maxmb,10)*1024*1024;
  var minD=parseInt(form.dataset.min,10), maxD=parseInt(form.dataset.max,10);
  var input=document.getElementById('file');
  var drop=document.getElementById('drop');
  var emptyBox=document.getElementById('dropEmpty');
  var fileRow=document.getElementById('fileRow');
  var fileName=document.getElementById('fileName');
  var fileSize=document.getElementById('fileSize');
  var clearBtn=document.getElementById('fileClear');
  var sendBtn=document.getElementById('sendBtn');
  var number=document.getElementById('number');
  var numHint=document.getElementById('numHint');
  var ccSel=document.getElementById('cc');
  var pvEmpty=document.getElementById('previewEmpty');
  var pvDoc=document.getElementById('previewDoc');
  var pvFrame=document.getElementById('previewFrame');
  var pvTag=document.getElementById('previewTag');
  var url=null, fileOk=false, numOk=false;

  function human(b){ if(b<1024)return b+' B';
    if(b<1048576)return (b/1024).toFixed(0)+' KB';
    return (b/1048576).toFixed(1)+' MB'; }
  function updateSend(){ sendBtn.disabled=!(fileOk && numOk); }

  // --- country + phone formatting (mirrors server format_fax_number) ---
  function isNANP(){ return ccSel.value==='1'; }
  function digitsOf(s){ return s.replace(/\\D/g,''); }
  function formatUS(d){
    d=d.slice(0,10);
    if(d.length>6) return d.slice(0,3)+'-'+d.slice(3,6)+'-'+d.slice(6);
    if(d.length>3) return d.slice(0,3)+'-'+d.slice(3);
    return d;
  }
  // live-format the field as typed, preserving the caret by digit position
  function reformat(keepCaret){
    var before = keepCaret ? digitsOf(number.value.slice(0,number.selectionStart)).length : -1;
    var d=digitsOf(number.value);
    number.value = isNANP() ? formatUS(d) : d;
    if(keepCaret){
      var pos=0, seen=0;
      while(pos<number.value.length && seen<before){
        if(/\\d/.test(number.value.charAt(pos))) seen++; pos++;
      }
      try{ number.setSelectionRange(pos,pos); }catch(_){}
    }
  }
  function validateNum(){
    var d=digitsOf(number.value);
    if(isNANP()){
      numOk = d.length===10 && '23456789'.indexOf(d.charAt(0))>=0 && '23456789'.indexOf(d.charAt(3))>=0;
      if(!number.value){ numHint.textContent=''; numHint.className='fieldnote'; }
      else if(numOk){ numHint.textContent='✓ +1 '+formatUS(d); numHint.className='fieldnote ok'; }
      else if(d.length>=1 && '01'.indexOf(d.charAt(0))>=0){
        numHint.textContent='area code can’t start with 0 or 1'; numHint.className='fieldnote bad'; }
      else { numHint.textContent=d.length+'/10 digits'; numHint.className='fieldnote bad'; }
    } else {
      numOk = d.length>=minD && d.length<=maxD;
      if(!number.value){ numHint.textContent=''; numHint.className='fieldnote'; }
      else if(numOk){ numHint.textContent='✓ +'+ccSel.value+' '+d; numHint.className='fieldnote ok'; }
      else { numHint.textContent=d.length+' digits · need '+minD+'–'+maxD; numHint.className='fieldnote bad'; }
    }
    number.classList.toggle('bad', !!number.value && !numOk);
    updateSend();
  }
  number.addEventListener('input', function(){ reformat(true); validateNum(); });
  ccSel.addEventListener('change', function(){
    number.placeholder = isNANP() ? '972-555-0123' : 'national number';
    reformat(false); validateNum(); number.focus();
  });

  // default the country from the browser locale (e.g. en-GB -> GB)
  (function(){
    try{
      var langs=(navigator.languages && navigator.languages.length)
                ? navigator.languages : [navigator.language];
      var region=null;
      for(var i=0;i<langs.length && !region;i++){
        var m=(langs[i]||'').match(/[-_]([A-Za-z]{2})\\b/);
        if(m) region=m[1].toUpperCase();
      }
      if(region){
        var opt=ccSel.querySelector('option[data-iso="'+region+'"]');
        if(opt){
          ccSel.selectedIndex=Array.prototype.indexOf.call(ccSel.options,opt);
          number.placeholder=isNANP()?'972-555-0123':'national number';
        }
      }
    }catch(_){}
  })();

  function reset(){
    if(url){URL.revokeObjectURL(url); url=null;}
    input.value=''; fileOk=false;
    fileRow.style.display='none'; emptyBox.style.display='';
    drop.classList.remove('has');
    pvDoc.style.display='none'; pvFrame.removeAttribute('src');
    pvEmpty.style.display=''; pvTag.textContent='no document'; pvTag.style.color='var(--faint)';
    updateSend();
  }

  function show(file){
    if(!file) return;
    var isPdf=file.type==='application/pdf'||/\\.pdf$/i.test(file.name);
    if(!isPdf){ flash('Only PDF files are accepted.'); reset(); return; }
    if(file.size>maxBytes){ flash('That PDF is larger than the '+(maxBytes/1048576)+' MB limit.'); reset(); return; }
    fileName.textContent=file.name;
    fileSize.textContent=human(file.size);
    fileRow.style.display=''; emptyBox.style.display='none'; drop.classList.add('has');
    if(url) URL.revokeObjectURL(url);
    url=URL.createObjectURL(file);
    pvFrame.src=url+'#toolbar=1&view=FitH';
    pvDoc.style.display=''; pvEmpty.style.display='none';
    pvTag.textContent=human(file.size); pvTag.style.color='var(--muted)';
    fileOk=true; updateSend();
  }

  function flash(text){
    var box=document.querySelector('.toasts');
    var t=document.createElement('div'); t.className='toast err';
    t.innerHTML='<div class="stripe"></div><div class="msg"></div>';
    t.querySelector('.msg').textContent=text; box.appendChild(t);
    setTimeout(function(){t.style.transition='opacity .4s, transform .4s';
      t.style.opacity=0; t.style.transform='translateX(16px)';
      setTimeout(function(){t.remove();},400);},4200);
  }

  input.addEventListener('change',function(){ show(input.files[0]); });
  clearBtn.addEventListener('click',function(e){ e.preventDefault(); e.stopPropagation(); reset(); });

  ['dragenter','dragover'].forEach(function(ev){
    drop.addEventListener(ev,function(e){ e.preventDefault(); drop.classList.add('over'); });
  });
  ['dragleave','dragend','drop'].forEach(function(ev){
    drop.addEventListener(ev,function(e){ e.preventDefault(); drop.classList.remove('over'); });
  });
  drop.addEventListener('drop',function(e){
    var f=e.dataTransfer.files[0]; if(!f) return;
    try{ var dt=new DataTransfer(); dt.items.add(f); input.files=dt.files; }catch(_){}
    show(f);
  });
})();
</script>
"""

def page(tpl, **ctx):
    ctx.setdefault("fonts", FONTS)
    body = render_template_string(tpl, **ctx)
    return render_template_string(BASE, body=body, **ctx)

# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.get("/login")
def login_get():
    return page(LOGIN, title="Sign in", csrf=csrf_token(),
                next=request.args.get("next", ""), dry=DRY_RUN)

@app.post("/login")
def login():
    check_csrf()
    if hmac.compare_digest(request.form.get("password", ""), PASSWORD):
        session["auth"] = True
        session.permanent = True
        nxt = request.form.get("next") or url_for("index")
        if not nxt.startswith("/"):
            nxt = url_for("index")
        return redirect(nxt)
    flash("Wrong password.", "err")
    return redirect(url_for("login_get"))

@app.post("/logout")
def logout():
    check_csrf()
    session.clear()
    return redirect(url_for("login_get"))

@app.get("/")
@login_required
def index():
    live = active_cups_jobs()
    jobs = recent_jobs()
    for j in jobs:
        j["when"] = time.strftime("%m-%d %H:%M", time.localtime(j.get("ts", 0)))
        j["live"] = live.get(j.get("job_id"))
    return page(INDEX, title="Send a fax", csrf=csrf_token(), jobs=jobs,
                max_mb=MAX_MB, queue=QUEUE, dry=DRY_RUN,
                phone_min=PHONE_MIN, phone_max=PHONE_MAX,
                countries=COUNTRIES, default_cc=DEFAULT_CC)

@app.post("/send")
@login_required
def send():
    check_csrf()
    display, dial = format_fax_number(request.form.get("cc", ""),
                                      request.form.get("number", ""))
    if not dial:
        flash("Enter a valid fax number for the selected country "
              "(US/Canada: 10 digits, NPA-NXX-XXXX).", "err")
        return redirect(url_for("index"))

    f = request.files.get("file")
    if not f or not f.filename:
        flash("No file selected.", "err")
        return redirect(url_for("index"))
    if not f.filename.lower().endswith(".pdf"):
        flash("Only PDF files are accepted.", "err")
        return redirect(url_for("index"))

    head = f.stream.read(5)
    f.stream.seek(0)
    if not looks_like_pdf(head):
        flash("That file doesn't look like a PDF.", "err")
        return redirect(url_for("index"))

    safe = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(f.filename))[:80]
    dest = UPLOAD_DIR / f"{int(time.time())}_{secrets.token_hex(4)}_{safe}"
    f.save(dest)

    ok, job_id, msg = send_fax(dest, dial, request.form.get("pagesize", "Letter"))

    record_job({
        "number": display, "filename": safe, "ok": ok,
        "job_id": job_id, "message": msg,
    })
    if ok:
        flash(f"Sent to {display}. {('Job ' + job_id) if job_id else ''}", "ok")
    else:
        flash(f"Failed: {msg}", "err")
    return redirect(url_for("index"))

@app.get("/favicon.svg")
@app.get("/favicon.ico")
def favicon():
    return Response(FAVICON_SVG, mimetype="image/svg+xml",
                   headers={"Cache-Control": "max-age=86400"})

@app.get("/healthz")
def healthz():
    return Response("ok\n", mimetype="text/plain")

if __name__ == "__main__":
    bind = os.environ.get("FAX_BIND", "0.0.0.0")
    port = int(os.environ.get("FAX_PORT", "8080"))
    print(f"faxweb: queue={QUEUE} dry_run={DRY_RUN} bind={bind}:{port} data={DATA_DIR}")
    app.run(host=bind, port=port)
