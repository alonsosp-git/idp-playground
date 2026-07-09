# -*- coding: utf-8 -*-
"""
IDP-Playground -- OIDC Test Client
File : testclient_oidc.py
Port : 5000
Needs: IDP-Playground (idp_playground_server.py) running on port 8080

This file is intentionally named testclient_oidc.py so it
never conflicts with the parent IDP-Playground process.  It is launched
by IDP-Playground's UI and runs under Python's built-in wsgiref server,
which has no reloader, no socket-FD inheritance, and no Werkzeug
debug tooling -- making it safe to spawn as a subprocess on Windows.

Install: pip install flask requests
Run    : python testclient_oidc.py
"""

import os, sys, json, secrets, base64, datetime

# Force stdout and stderr to UTF-8 on Windows (CP1252 by default).
# Must be done before any print() calls or imports that print.
if sys.stdout.encoding and sys.stdout.encoding.upper() not in ("UTF-8", "UTF8"):
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import requests
from wsgiref.simple_server import make_server, WSGIRequestHandler
from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify

# ── silence wsgiref request logs ──────────────────────────
class _QuietHandler(WSGIRequestHandler):
    def log_message(self, fmt, *args):
        print(f"  [{self.address_string()}] {fmt % args}", flush=True)

# ── App ───────────────────────────────────────────────────
client = Flask(__name__)
client.secret_key = "idp-playground-oidc-client-fixed-session-key-2024"
# Unique cookie name so the four localhost demo apps don't overwrite each
# other's session cookie (cookies are shared across ports on the same host).
client.config["SESSION_COOKIE_NAME"] = "va_oidc_session"

# Build marker — bump this whenever the file changes so you can confirm in the
# browser which build is actually running (visit /version).
BUILD_VERSION = "2026-06-11-rebrand-dropzone-18"

# Make Jinja tolerant: an undefined variable renders empty instead of crashing
# the whole page with a 500. This guarantees the MFA challenge page can always
# render even if a future template variable is missing.
from jinja2 import ChainableUndefined as _ChainableUndefined
client.jinja_env.undefined = _ChainableUndefined

IDPPLAYGROUND_BASE = os.environ.get("IDPPLAYGROUND_BASE", "http://localhost:8080")
PUBLIC_URL     = os.environ.get("OIDC_PUBLIC_URL", "http://localhost:5000")
REDIRECT_URI   = PUBLIC_URL + "/auth/callback"
SCOPES         = "openid profile email groups"
_client_id     = None
_client_secret = None
_our_app_id    = None    # FSApplication.id — needed for app-level MFA check


@client.route("/version")
def _version():
    return {"build": BUILD_VERSION}



@client.errorhandler(Exception)
def _show_error(e):
    """Surface the real error in the browser instead of a blank 500 page."""
    from werkzeug.exceptions import HTTPException
    import traceback as _tb
    code = e.code if isinstance(e, HTTPException) else 500
    tb = _tb.format_exc()
    html = (
        "<html><head><title>IDP-Playground Client Error</title>"
        "<style>body{background:#0b0f1a;color:#e6edf3;font-family:monospace;padding:30px}"
        "h1{color:#f87171}pre{background:#11161f;border:1px solid #1f3349;border-radius:8px;"
        "padding:16px;overflow:auto;white-space:pre-wrap}a{color:#38b6ff}</style></head><body>"
        "<h1>Client error (" + str(code) + ")</h1>"
        "<p>" + type(e).__name__ + ": " + str(e) + "</p>"
        "<pre>" + tb + "</pre>"
        "<p><a href='/'>Back to start</a> &middot; <a href='/logout'>Logout / clear session</a></p>"
        "</body></html>")
    return html, code



# ── Auto-register with IDP-Playground ──────────────────────────
def _get_or_register():
    global _client_id, _client_secret, _our_app_id
    if _client_id:
        return True
    try:
        resp = requests.get(f"{IDPPLAYGROUND_BASE}/api/fs/applications", timeout=4)
        for a in resp.json():
            if a["name"] == "OIDC Test Client":
                _client_id  = a["client_id"]
                _our_app_id = a["id"]
                rot = requests.post(
                    f"{IDPPLAYGROUND_BASE}/api/fs/applications/{a['id']}/rotate-secret",
                    timeout=4)
                _client_secret = rot.json().get("client_secret", "")
                print(f"  [IDP-Playground] Reusing app  client_id={_client_id[:16]}…", flush=True)
                return True
        reg = requests.post(f"{IDPPLAYGROUND_BASE}/api/fs/applications", json={
            "name":          "OIDC Test Client",
            "description":   "Auto-registered test client at localhost:5000",
            "redirect_uris": REDIRECT_URI,
            "allowed_scopes": SCOPES,
            "protocol":      "OIDC",
            "icon_emoji":    "🧪",
            "brand_color":   "#34d399",
            "token_lifetime": 3600,
            "refresh_enabled": True,
        }, timeout=4)
        d = reg.json()
        _client_id     = d["client_id"]
        _client_secret = d["client_secret"]
        _our_app_id    = d.get("id")
        print(f"  [IDP-Playground] App registered  client_id={_client_id[:16]}…", flush=True)
        return True
    except Exception as exc:
        print(f"  [IDP-Playground] Cannot connect: {exc}", flush=True)
        return False


def _decode_payload(token: str) -> dict:
    try:
        part = token.split(".")[1]
        pad  = part + "=" * ((4 - len(part) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(pad))
    except Exception:
        return {}


# ── HTML template ─────────────────────────────────────────
_TMPL = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IDP-Playground — Test Client</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;700&family=Outfit:wght@400;700;800;900&display=swap" rel="stylesheet">
<style>
:root{--bg:#05080d;--bg2:#090e16;--bg3:#0e1620;--b:1px solid #172333;--b2:1px solid #1f3349;--ds:#38b6ff;--fs:#a78bfa;--v:#e8ff47;--green:#34d399;--red:#f87171;--orange:#fb923c;--text:#d4e4f5;--muted:#4a6685;}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Outfit',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;padding:36px 20px;}
body::before{content:'';position:fixed;inset:0;pointer-events:none;background-image:linear-gradient(rgba(56,182,255,.03) 1px,transparent 1px),linear-gradient(90deg,rgba(56,182,255,.03) 1px,transparent 1px);background-size:44px 44px;z-index:0;}
.wrap{max-width:820px;margin:0 auto;position:relative;z-index:1;}
.hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:28px;padding-bottom:18px;border-bottom:var(--b);flex-wrap:wrap;gap:10px;}
.logo{display:flex;align-items:center;gap:10px;}
.hex{width:38px;height:38px;background:var(--green);clip-path:polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%);display:flex;align-items:center;justify-content:center;font-size:17px;box-shadow:0 0 18px rgba(52,211,153,.4);}
.logo-name{font-size:17px;font-weight:900;color:#fff;}
.logo-sub{font-family:'IBM Plex Mono',monospace;font-size:8px;color:var(--muted);letter-spacing:2px;}
.badge{display:flex;align-items:center;gap:6px;border-radius:20px;padding:4px 12px;font-family:'IBM Plex Mono',monospace;font-size:9px;}
.badge::before{content:'';width:6px;height:6px;border-radius:50%;flex-shrink:0;}
.badge-on{background:rgba(52,211,153,.08);border:var(--b2);color:var(--green);}
.badge-on::before{background:var(--green);box-shadow:0 0 5px var(--green);}
.badge-off{background:rgba(248,113,113,.08);border:1px solid rgba(248,113,113,.2);color:var(--red);}
.badge-off::before{background:var(--red);}
.card{background:var(--bg2);border:var(--b);border-radius:11px;overflow:hidden;margin-bottom:14px;}
.ch{display:flex;align-items:center;justify-content:space-between;padding:13px 18px;border-bottom:var(--b);}
.ct{font-size:14px;font-weight:700;}
.cb{padding:18px;}
.btn{display:inline-flex;align-items:center;gap:6px;padding:9px 18px;border-radius:8px;font-family:'Outfit',sans-serif;font-weight:700;font-size:13px;cursor:pointer;border:none;text-decoration:none;transition:all .18s;}
.btn-green{background:var(--green);color:#000;box-shadow:0 0 14px rgba(52,211,153,.3);}
.btn-green:hover{box-shadow:0 0 26px rgba(52,211,153,.5);transform:translateY(-1px);}
.btn-red{background:rgba(248,113,113,.1);color:var(--red);border:1px solid rgba(248,113,113,.25);}
.btn-ghost{background:transparent;color:var(--muted);border:var(--b2);}
.btn-ghost:hover{border-color:var(--ds);color:var(--ds);}
.sp{display:inline-flex;align-items:center;gap:4px;font-family:'IBM Plex Mono',monospace;font-size:9px;}
.sp::before{content:'';width:5px;height:5px;border-radius:50%;flex-shrink:0;}
.sp-ok::before{background:var(--green);box-shadow:0 0 4px var(--green);}
.sp-err::before{background:var(--red);}
.sess{display:flex;align-items:center;justify-content:space-between;background:rgba(52,211,153,.05);border:1px solid rgba(52,211,153,.15);border-radius:10px;padding:12px 18px;margin-bottom:20px;flex-wrap:wrap;gap:10px;}
.av{width:36px;height:36px;border-radius:9px;background:rgba(56,182,255,.2);color:var(--ds);display:flex;align-items:center;justify-content:center;font-size:15px;font-weight:900;}
.chip{display:inline-flex;align-items:center;padding:3px 9px;border-radius:20px;font-size:10px;font-family:'IBM Plex Mono',monospace;}
.chip-g{background:rgba(52,211,153,.1);color:var(--green);border:1px solid rgba(52,211,153,.2);}
.chip-b{background:rgba(56,182,255,.1);color:var(--ds);border:1px solid rgba(56,182,255,.2);}
.chip-p{background:rgba(167,139,250,.1);color:var(--fs);border:1px solid rgba(167,139,250,.2);}
.mr{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid rgba(23,35,51,.5);font-size:12px;}
.mr:last-child{border-bottom:none;}
.mk{font-family:'IBM Plex Mono',monospace;font-size:9px;color:var(--muted);}
.tbox{background:var(--bg);border:var(--b);border-radius:7px;padding:11px 13px;font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--green);word-break:break-all;overflow-wrap:anywhere;max-width:100%;line-height:1.7;cursor:pointer;}
.tbox:hover{border-color:var(--ds);}
pre.dec{font-family:'IBM Plex Mono',monospace;font-size:11px;background:var(--bg);border:var(--b);border-radius:7px;padding:12px;line-height:1.7;color:var(--green);white-space:pre-wrap;word-break:break-all;overflow-wrap:anywhere;max-width:100%;}
.gtag{display:inline-flex;align-items:center;gap:4px;padding:4px 10px;border-radius:6px;font-size:11px;font-weight:700;background:rgba(167,139,250,.1);color:var(--fs);border:1px solid rgba(167,139,250,.2);margin:3px;}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:14px;}
.fi{width:100%;background:var(--bg);border:var(--b2);border-radius:8px;padding:10px 13px;color:var(--text);font-family:'Outfit',sans-serif;font-size:13px;outline:none;}
.fi:focus{border-color:var(--ds);}
.fl{display:block;font-size:11px;font-weight:700;color:var(--muted);letter-spacing:.5px;margin-bottom:5px;}
.fg{margin-bottom:12px;}
.hint{background:rgba(232,255,71,.04);border:1px solid rgba(232,255,71,.12);border-left:3px solid var(--v);border-radius:0 8px 8px 0;padding:11px 14px;font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);line-height:1.8;margin-top:14px;}
.hint strong{color:var(--v);}
.err{background:rgba(248,113,113,.08);border:1px solid rgba(248,113,113,.2);border-radius:7px;padding:9px 12px;font-size:12px;color:var(--red);margin-bottom:12px;font-family:'IBM Plex Mono',monospace;}
.navbtn{background:transparent;border:1px solid transparent;border-radius:8px;padding:8px 14px;font-family:'Outfit',sans-serif;font-weight:700;font-size:12px;color:var(--muted);cursor:pointer;transition:all .15s;}
.navbtn:hover{color:var(--text);background:var(--bg3);}
.navbtn.active{background:rgba(56,182,255,.12);color:var(--ds);border-color:rgba(56,182,255,.25);}
::-webkit-scrollbar{width:5px;} ::-webkit-scrollbar-track{background:transparent;} ::-webkit-scrollbar-thumb{background:#1f3349;border-radius:3px;}
</style>
</head>
<body>
<div class="wrap">
 <div class="hdr">
  <div class="logo">
   <div class="hex">🧪</div>
   <div>
    <div class="logo-name">OIDC Test Client</div>
    <div class="logo-sub">IDPPLAYGROUND LIVE TEST · localhost:5000</div>
   </div>
  </div>
  {% if connected %}
  <div class="badge badge-on">IDPPLAYGROUND :8080 CONNECTED</div>
  {% else %}
  <div class="badge badge-off">IDPPLAYGROUND :8080 OFFLINE</div>
  {% endif %}
 </div>

 {% if not connected %}
 <!-- ── Not connected ── -->
 <div class="card">
  <div class="ch"><div class="ct">⚠ IDP-Playground Not Reachable</div></div>
  <div class="cb" style="font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--muted);line-height:1.9">
   This test client needs IDP-Playground running at <strong style="color:var(--v)">http://localhost:8080</strong><br><br>
   Start it from the IDP-Playground UI → sidebar → <strong style="color:var(--v)">Test App → ▶ Start</strong><br>
   or run manually:<br><br>
   <span style="color:var(--green)">python idp_playground_server.py</span><br><br>
   Then refresh this page.
  </div>
 </div>

 {% elif user %}
 <!-- ── Authenticated ── -->
 <div class="sess">
  <div style="display:flex;align-items:center;gap:10px">
   <div class="av">{{ user.thumbnail_letter or user.display_name[0] }}</div>
   <div>
    <div style="font-weight:700;font-size:14px">{{ user.display_name }}</div>
    <div style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted)">{{ user.upn }}</div>
   </div>
  </div>
  <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
   <span class="chip chip-g">✓ Authenticated</span>
   <span class="chip chip-b">OIDC · RS256</span>
   {% if user.mfa_enabled %}<span class="chip chip-p">MFA: {{ user.mfa_method|upper }}</span>{% endif %}
   <a href="/logout" class="btn btn-red" style="padding:5px 12px;font-size:11px">Sign out</a>
  </div>
 </div>

 <!-- ── App navigation menu (demo) ── -->
 <div id="appnav" style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:20px;padding:6px;background:var(--bg2);border:var(--b);border-radius:11px">
  <button class="navbtn active" data-view="dashboard" onclick="nav('dashboard')">🏠 Dashboard</button>
  <button class="navbtn" data-view="profile" onclick="nav('profile')">👤 Profile</button>
  <button class="navbtn" data-view="token" onclick="nav('token')">🎫 Token</button>
  <button class="navbtn" data-view="groups" onclick="nav('groups')">👥 Groups</button>
  <button class="navbtn" data-view="api" onclick="nav('api')">🔌 Protected API</button>
  <button class="navbtn" data-view="settings" onclick="nav('settings')">⚙ Settings</button>
 </div>

 <!-- ── Dashboard view ── -->
 <div class="view" id="view-dashboard">
  <div class="card">
   <div class="ch"><div class="ct">🏠 Dashboard</div><span style="font-family:'IBM Plex Mono',monospace;font-size:9px;color:var(--muted)">home</span></div>
   <div class="cb">
    <div style="font-size:14px;font-weight:700;margin-bottom:6px">Welcome back, {{ user.given_name or user.display_name }}.</div>
    <div style="font-size:12px;color:var(--muted);line-height:1.8;margin-bottom:16px">
     You are signed in to the OIDC Test Client via IDP-Playground single sign-on. Use the menu above to
     move between sections. This demonstrates how a real application navigates while holding an
     authenticated session and a signed token.
    </div>
    <div class="g2">
     <div style="background:var(--bg3);border-radius:9px;padding:14px">
      <div class="mk" style="margin-bottom:6px">SESSION STATUS</div>
      <div style="font-size:13px;font-weight:700;color:var(--green)">● Active</div>
     </div>
     <div style="background:var(--bg3);border-radius:9px;padding:14px">
      <div class="mk" style="margin-bottom:6px">TOKEN EXPIRES</div>
      <div style="font-size:13px;font-weight:700">{{ exp_str or '—' }}</div>
     </div>
     <div style="background:var(--bg3);border-radius:9px;padding:14px">
      <div class="mk" style="margin-bottom:6px">AUTH METHOD</div>
      <div style="font-size:13px;font-weight:700;color:var(--fs)">{{ user.mfa_method|upper if user.mfa_enabled else 'PASSWORD' }}</div>
     </div>
     <div style="background:var(--bg3);border-radius:9px;padding:14px">
      <div class="mk" style="margin-bottom:6px">GROUPS</div>
      <div style="font-size:13px;font-weight:700">{{ claims.get('groups', [])|length }}</div>
     </div>
    </div>
    <div style="margin-top:14px"><div class="mk" style="margin-bottom:5px">LIVE SERVER RESPONSE (GET /api/section/dashboard)</div>
     <pre class="dec" id="live-dashboard" style="display:none"></pre></div>
   </div>
  </div>
 </div>

 <!-- ── Profile view ── -->
 <div class="view" id="view-profile" style="display:none">
  <div class="card">
   <div class="ch"><div class="ct">👤 User Attributes</div></div>
   <div class="cb">
    <div class="mr"><span class="mk">display_name</span><strong>{{ user.display_name }}</strong></div>
    <div class="mr"><span class="mk">sam_account</span><span>{{ user.sam_account }}</span></div>
    <div class="mr"><span class="mk">email</span><span>{{ user.email or '—' }}</span></div>
    <div class="mr"><span class="mk">department</span><span>{{ user.department or '—' }}</span></div>
    <div class="mr"><span class="mk">title</span><span>{{ user.title or '—' }}</span></div>
    <div class="mr"><span class="mk">company</span><span>{{ user.company or '—' }}</span></div>
    <div class="mr"><span class="mk">mfa_enabled</span><span class="sp {{ 'sp-ok' if user.mfa_enabled else 'sp-err' }}">{{ user.mfa_enabled }}</span></div>
    <div style="margin-top:14px"><div class="mk" style="margin-bottom:5px">LIVE SERVER RESPONSE (GET /api/section/profile — refetches from IDP-Playground)</div>
     <pre class="dec" id="live-profile" style="display:none"></pre></div>
   </div>
  </div>
 </div>

 <!-- ── Token view ── -->
 <div class="view" id="view-token" style="display:none">
  <div class="card">
   <div class="ch"><div class="ct">🎫 Token Claims</div></div>
   <div class="cb">
    <div class="mr"><span class="mk">iss</span><code style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--fs)">{{ claims.iss }}</code></div>
    <div class="mr"><span class="mk">sub</span><span style="font-size:10px;font-family:'IBM Plex Mono',monospace">{{ claims.sub }}</span></div>
    <div class="mr"><span class="mk">aud</span><span style="font-size:10px;font-family:'IBM Plex Mono',monospace">{{ claims.aud }}</span></div>
    <div class="mr"><span class="mk">scope</span><span style="font-size:11px">{{ claims.scope }}</span></div>
    <div class="mr"><span class="mk">expires</span><span style="font-size:11px">{{ exp_str }}</span></div>
    {% if claims.get('act') %}<div class="mr"><span class="mk">act (impersonator)</span><span style="font-size:10px;color:var(--orange)">{{ claims.act.sub }}</span></div>{% endif %}
   </div>
  </div>
  <div class="card">
   <div class="ch"><div class="ct">Raw JWT</div><span style="font-family:'IBM Plex Mono',monospace;font-size:9px;color:var(--muted)">click to copy</span></div>
   <div class="cb">
    <div class="tbox" onclick="navigator.clipboard?.writeText(this.dataset.t)" data-t="{{ token }}" title="Click to copy">{{ token[:90] }}…</div>
    <div style="font-family:'IBM Plex Mono',monospace;font-size:9px;color:var(--muted);margin:12px 0 5px;text-transform:uppercase;letter-spacing:1px">Decoded Payload</div>
    <pre class="dec">{{ decoded }}</pre>
    <div style="margin-top:12px"><div class="mk" style="margin-bottom:5px">LIVE SERVER RESPONSE (GET /api/section/token)</div>
     <pre class="dec" id="live-token" style="display:none"></pre></div>
   </div>
  </div>
 </div>

 <!-- ── Groups view ── -->
 <div class="view" id="view-groups" style="display:none">
  <div class="card">
   <div class="ch"><div class="ct">👥 Group Memberships</div></div>
   <div class="cb">
    {% for g in claims.get('groups', []) %}<span class="gtag">👥 {{ g }}</span>{% endfor %}
    {% if not claims.get('groups') %}<span style="color:var(--muted);font-size:12px">No group claims in token</span>{% endif %}
    <div style="margin-top:14px"><div class="mk" style="margin-bottom:5px">LIVE SERVER RESPONSE (GET /api/section/groups)</div>
     <pre class="dec" id="live-groups" style="display:none"></pre></div>
   </div>
  </div>
 </div>

 <!-- ── Protected API view ── -->
 <div class="view" id="view-api" style="display:none">
  <div class="card">
   <div class="ch"><div class="ct">🔌 Protected API Call</div></div>
   <div class="cb">
    <div style="font-size:12px;color:var(--muted);line-height:1.8;margin-bottom:14px">
     This calls the app's own protected endpoint <code style="color:var(--green)">/api/me</code>, which
     requires a valid session. It returns your identity and token claims — the kind of call a SPA makes
     after login.
    </div>
    <button class="btn btn-green" onclick="callApi()">Call /api/me →</button>
    <pre class="dec" id="api-out" style="margin-top:14px;display:none"></pre>
   </div>
  </div>
 </div>

 <!-- ── Settings view ── -->
 <div class="view" id="view-settings" style="display:none">
  <div class="card">
   <div class="ch"><div class="ct">⚙ Settings</div></div>
   <div class="cb">
    <div class="mr"><span class="mk">client</span><span>OIDC Test Client</span></div>
    <div class="mr"><span class="mk">redirect_uri</span><span style="font-size:10px;font-family:'IBM Plex Mono',monospace">http://localhost:5000/auth/callback</span></div>
    <div class="mr"><span class="mk">scopes</span><span style="font-size:11px">openid profile email groups</span></div>
    <div class="mr"><span class="mk">idp</span><span style="font-size:11px;color:var(--ds)">IDP-Playground @ :8080</span></div>
    <div style="margin:14px 0"><div class="mk" style="margin-bottom:5px">LIVE SERVER RESPONSE (GET /api/section/settings)</div>
     <pre class="dec" id="live-settings" style="display:none"></pre></div>
    <div style="margin-top:16px">
     <a href="/logout" class="btn btn-red">Sign out of this app</a>
    </div>
   </div>
  </div>
 </div>

 {% else %}
 <!-- ── Login wall ── -->
 <div class="card" style="max-width:420px;margin:0 auto">
  <div class="ch"><div class="ct">🔒 Authentication Required</div></div>
  <div class="cb" style="text-align:center;padding:28px 24px">
   <div style="font-size:48px;margin-bottom:12px">🔒</div>
   <div style="font-size:16px;font-weight:700;margin-bottom:6px">This app is protected by IDP-Playground</div>
   <div style="font-size:12px;color:var(--muted);margin-bottom:22px;line-height:1.7">
    Sign in to access the application.<br>
    Your credentials are validated against IDP-DS.
   </div>
   <a href="/login" class="btn btn-green" style="display:inline-flex;margin-bottom:16px">Sign in with IDP-Playground →</a>
   <div class="hint">
    <strong>Demo accounts:</strong><br>
    administrator@corp.idp-playground.local / <strong>Admin@IDP-Playground1</strong><br>
    john.smith@corp.idp-playground.local &nbsp;/ <strong>Welcome@1</strong><br>
    maria.jones@corp.idp-playground.local / <strong>Welcome@1</strong>
   </div>
  </div>
 </div>
 {% endif %}

</div>

<script>
async function nav(view){
  document.querySelectorAll('.view').forEach(function(v){ v.style.display='none'; });
  var el=document.getElementById('view-'+view);
  if(el) el.style.display='block';
  document.querySelectorAll('.navbtn').forEach(function(b){
    b.classList.toggle('active', b.dataset.view===view);
  });
  window.scrollTo(0,0);
  // Fetch this section from the server so navigating generates real HTTP
  // traffic that the capture panel records. The 'api' tab has its own button.
  if(view !== 'api'){
    try{
      var r = await fetch('/api/section/' + view);
      var d = await r.json();
      var live = document.getElementById('live-' + view);
      if(live){
        live.style.display = 'block';
        live.textContent = JSON.stringify(d, null, 2);
      }
    }catch(e){ /* navigation still works even if fetch fails */ }
  }
}
async function callApi(){
  var out=document.getElementById('api-out');
  out.style.display='block';
  out.textContent='Calling /api/me ...';
  try{
    var r=await fetch('/api/me');
    var d=await r.json();
    out.textContent=JSON.stringify(d,null,2);
  }catch(e){
    out.textContent='Error: '+e.message;
  }
}
// Fetch the dashboard section on first load too (generates initial traffic)
window.addEventListener('DOMContentLoaded', function(){
  if(document.getElementById('view-dashboard')){ nav('dashboard'); }
});
</script>

<div id="cap-panel" style="position:fixed;bottom:16px;right:16px;z-index:9000;font-family:'Outfit',sans-serif">
  <div id="cap-bar" style="display:flex;align-items:center;gap:8px;background:#0e1620;border:1px solid #1f3349;border-radius:10px;padding:8px 12px;box-shadow:0 8px 30px rgba(0,0,0,.5)">
    <span id="cap-dot" style="width:9px;height:9px;border-radius:50%;background:#4a6685;display:inline-block"></span>
    <span style="font-size:11px;font-weight:700;color:#d4e4f5;font-family:'IBM Plex Mono',monospace">TRAFFIC CAPTURE</span>
    <span id="cap-count" style="font-size:10px;color:#4a6685;font-family:'IBM Plex Mono',monospace">0</span>
    <button id="cap-toggle" onclick="capToggle()" style="border:none;border-radius:7px;padding:6px 12px;font-weight:700;font-size:12px;cursor:pointer;background:#34d399;color:#000">Start</button>
    <button onclick="capDownload()" style="border:1px solid #1f3349;border-radius:7px;padding:6px 10px;font-size:12px;cursor:pointer;background:transparent;color:#4a6685">Download</button>
    <button onclick="capView()" style="border:1px solid #1f3349;border-radius:7px;padding:6px 10px;font-size:12px;cursor:pointer;background:transparent;color:#4a6685">View</button>
    <button onclick="capClear()" style="border:1px solid #1f3349;border-radius:7px;padding:6px 10px;font-size:12px;cursor:pointer;background:transparent;color:#f87171">Clear</button>
  </div>
  <div id="cap-list" style="display:none;margin-top:8px;width:560px;max-height:340px;overflow:auto;background:#05080d;border:1px solid #1f3349;border-radius:10px;padding:10px;font-family:'IBM Plex Mono',monospace;font-size:10px;color:#d4e4f5"></div>
</div>
<script>
let _capActive=false;
async function capToggle(){
  const ep=_capActive?'/__capture/stop':'/__capture/start';
  const r=await fetch(ep,{method:'POST'});const d=await r.json();
  _capActive=d.active;capRender();
}
function capRender(){
  document.getElementById('cap-dot').style.background=_capActive?'#f87171':'#4a6685';
  const b=document.getElementById('cap-toggle');
  b.textContent=_capActive?'Stop':'Start';
  b.style.background=_capActive?'#f87171':'#34d399';
  b.style.color=_capActive?'#fff':'#000';
}
async function capPoll(){
  try{const r=await fetch('/__capture/status');const d=await r.json();
    _capActive=d.active;document.getElementById('cap-count').textContent=d.count;capRender();}catch(e){}
}
function capDownload(){
  const a=document.createElement('a');a.href='/__capture/download';
  a.download='idp-playground-traffic.json';a.click();
}
async function capClear(){await fetch('/__capture/clear',{method:'POST'});capPoll();
  document.getElementById('cap-list').style.display='none';}
function capRenderList(d){
  const l=document.getElementById('cap-list');
  if(!l) return;
  if(!d.entries.length){l.innerHTML='<div style="color:#4a6685">No traffic captured yet. Click Start, then use the app (navigate tabs, sign in, etc).</div>';return;}
  l.innerHTML=d.entries.slice().reverse().map(function(e){
    var col=e.direction==='outbound'?'#a78bfa':'#38b6ff';
    var sc=e.status>=400?'#f87171':(e.status>=300?'#fb923c':'#34d399');
    return '<div style="border-bottom:1px solid #111b27;padding:5px 0">'+
      '<span style="color:'+col+'">'+e.direction.toUpperCase()+'</span> '+
      '<span style="color:#e8ff47">'+e.method+'</span> '+
      '<span style="color:'+sc+'">'+(e.status||'')+'</span> '+
      '<span style="color:#4a6685">'+(e.duration_ms||'')+'ms</span><br>'+
      '<span style="color:#d4e4f5;word-break:break-all">'+(e.url||e.path||'')+'</span>'+
      (e.req_body?'<br><span style="color:#4a6685">req:</span> <span style="color:#8aa">'+
        (e.req_body+'').replace(/</g,'&lt;').slice(0,300)+'</span>':'')+
      '</div>';
  }).join('');
}
async function capRefreshList(){
  const l=document.getElementById('cap-list');
  if(!l || l.style.display==='none') return;
  try{const r=await fetch('/__capture/view');const d=await r.json();capRenderList(d);}catch(e){}
}
async function capView(){
  const l=document.getElementById('cap-list');
  if(l.style.display!=='none'){l.style.display='none';return;}
  l.style.display='block';
  await capRefreshList();
}
// Poll status always; refresh the open list every interval so new traffic
// appears live without needing to close and reopen the panel.
setInterval(function(){capPoll();capRefreshList();},1200);capPoll();
</script>
</body>
</html>"""


_LOGIN_TMPL = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>IDP-Playground — Sign In</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;700&family=Outfit:wght@400;700;800&display=swap" rel="stylesheet">
<style>
:root{--bg:#05080d;--bg2:#090e16;--b2:1px solid #1f3349;--ds:#38b6ff;--v:#e8ff47;--green:#34d399;--red:#f87171;--text:#d4e4f5;--muted:#4a6685;}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Outfit',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;}
.box{background:var(--bg2);border:var(--b2);border-radius:14px;padding:32px;width:100%;max-width:380px;box-shadow:0 0 50px rgba(56,182,255,.06);}
.logo{text-align:center;margin-bottom:24px;}
.hex{width:44px;height:44px;background:var(--v);clip-path:polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%);display:flex;align-items:center;justify-content:center;font-size:20px;margin:0 auto 10px;box-shadow:0 0 22px rgba(232,255,71,.4);}
.t{font-size:18px;font-weight:900;color:#fff;}
.s{font-family:'IBM Plex Mono',monospace;font-size:9px;color:var(--muted);letter-spacing:2px;margin-top:3px;}
.fg{margin-bottom:13px;}
.fl{display:block;font-size:11px;font-weight:700;color:var(--muted);letter-spacing:.5px;margin-bottom:5px;}
.fi{width:100%;background:var(--bg);border:var(--b2);border-radius:8px;padding:10px 13px;color:var(--text);font-family:'Outfit',sans-serif;font-size:13px;outline:none;}
.fi:focus{border-color:var(--ds);}
.btn{width:100%;padding:11px;border-radius:9px;font-family:'Outfit',sans-serif;font-weight:700;font-size:14px;cursor:pointer;border:none;background:var(--ds);color:#000;box-shadow:0 0 14px rgba(56,182,255,.3);transition:all .18s;}
.btn:hover{box-shadow:0 0 26px rgba(56,182,255,.5);}
.err{background:rgba(248,113,113,.08);border:1px solid rgba(248,113,113,.2);border-radius:7px;padding:8px 12px;font-size:12px;color:var(--red);margin-bottom:12px;font-family:'IBM Plex Mono',monospace;}
.hint{background:rgba(232,255,71,.04);border:1px solid rgba(232,255,71,.12);border-radius:7px;padding:10px 13px;font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);line-height:1.8;margin-top:14px;}
.hint strong{color:var(--v);}
</style>
</head>
<body>
<div class="box">
 <div class="logo">
  <div class="hex">🔐</div>
  <div class="t">IDP-Playground</div>
  <div class="s">SIGN IN TO CONTINUE</div>
 </div>
 <form method="POST" action="/auth">
  {% if error %}<div class="err">{{ error }}</div>{% endif %}
  <div class="fg"><label class="fl">UPN / EMAIL</label>
   <input class="fi" name="upn" placeholder="user@corp.idp-playground.local" required autocomplete="username"></div>
  <div class="fg"><label class="fl">PASSWORD</label>
   <input class="fi" name="password" type="password" placeholder="••••••••" required autocomplete="current-password"></div>
  <div id="imp-row" style="display:none">
   <div class="fg"><label class="fl">IMPERSONATE USER (UPN or email)</label>
    <input class="fi" name="impersonate" id="imp-input" placeholder="target.user@corp.idp-playground.local" autocomplete="off"></div>
   <div style="font-size:10px;color:#4a6685;font-family:'IBM Plex Mono',monospace;line-height:1.7;margin-bottom:10px">
    Sign in with your <strong style="color:#e8ff47">admin</strong> credentials above. The token is issued
    as the target user with an actor (act) claim recording who impersonated.
   </div>
  </div>
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;font-size:11px;color:#4a6685;cursor:pointer" onclick="toggleImp(event)">
   <input type="checkbox" id="imp-chk" style="cursor:pointer" onclick="event.stopPropagation();toggleImp(event)">
   <label for="imp-chk" style="cursor:pointer">Sign on behalf of another user (admin only)</label>
  </div>
  <button class="btn" type="submit">Sign In →</button>
 </form>
 <script>
 function toggleImp(ev){
   var c=document.getElementById('imp-chk'),r=document.getElementById('imp-row');
   if(ev && ev.target!==c){c.checked=!c.checked;}
   r.style.display=c.checked?'block':'none';
   if(!c.checked){document.getElementById('imp-input').value='';}
 }
 </script>
 <div class="hint">
  <strong>Demo accounts:</strong><br>
  administrator@corp.idp-playground.local<br>
  &nbsp;&nbsp;password: <strong>Admin@IDP-Playground1</strong><br>
  john.smith@corp.idp-playground.local<br>
  &nbsp;&nbsp;password: <strong>Welcome@1</strong>
 </div>
 <div style="text-align:center;margin-top:14px;font-size:9px;color:#2c4660;font-family:'IBM Plex Mono',monospace">build {{ build }}</div>
</div>

<div id="cap-panel" style="position:fixed;bottom:16px;right:16px;z-index:9000;font-family:'Outfit',sans-serif">
  <div id="cap-bar" style="display:flex;align-items:center;gap:8px;background:#0e1620;border:1px solid #1f3349;border-radius:10px;padding:8px 12px;box-shadow:0 8px 30px rgba(0,0,0,.5)">
    <span id="cap-dot" style="width:9px;height:9px;border-radius:50%;background:#4a6685;display:inline-block"></span>
    <span style="font-size:11px;font-weight:700;color:#d4e4f5;font-family:'IBM Plex Mono',monospace">TRAFFIC CAPTURE</span>
    <span id="cap-count" style="font-size:10px;color:#4a6685;font-family:'IBM Plex Mono',monospace">0</span>
    <button id="cap-toggle" onclick="capToggle()" style="border:none;border-radius:7px;padding:6px 12px;font-weight:700;font-size:12px;cursor:pointer;background:#34d399;color:#000">Start</button>
    <button onclick="capDownload()" style="border:1px solid #1f3349;border-radius:7px;padding:6px 10px;font-size:12px;cursor:pointer;background:transparent;color:#4a6685">Download</button>
    <button onclick="capView()" style="border:1px solid #1f3349;border-radius:7px;padding:6px 10px;font-size:12px;cursor:pointer;background:transparent;color:#4a6685">View</button>
    <button onclick="capClear()" style="border:1px solid #1f3349;border-radius:7px;padding:6px 10px;font-size:12px;cursor:pointer;background:transparent;color:#f87171">Clear</button>
  </div>
  <div id="cap-list" style="display:none;margin-top:8px;width:560px;max-height:340px;overflow:auto;background:#05080d;border:1px solid #1f3349;border-radius:10px;padding:10px;font-family:'IBM Plex Mono',monospace;font-size:10px;color:#d4e4f5"></div>
</div>
<script>
let _capActive=false;
async function capToggle(){
  const ep=_capActive?'/__capture/stop':'/__capture/start';
  const r=await fetch(ep,{method:'POST'});const d=await r.json();
  _capActive=d.active;capRender();
}
function capRender(){
  document.getElementById('cap-dot').style.background=_capActive?'#f87171':'#4a6685';
  const b=document.getElementById('cap-toggle');
  b.textContent=_capActive?'Stop':'Start';
  b.style.background=_capActive?'#f87171':'#34d399';
  b.style.color=_capActive?'#fff':'#000';
}
async function capPoll(){
  try{const r=await fetch('/__capture/status');const d=await r.json();
    _capActive=d.active;document.getElementById('cap-count').textContent=d.count;capRender();}catch(e){}
}
function capDownload(){
  const a=document.createElement('a');a.href='/__capture/download';
  a.download='idp-playground-traffic.json';a.click();
}
async function capClear(){await fetch('/__capture/clear',{method:'POST'});capPoll();
  document.getElementById('cap-list').style.display='none';}
function capRenderList(d){
  const l=document.getElementById('cap-list');
  if(!l) return;
  if(!d.entries.length){l.innerHTML='<div style="color:#4a6685">No traffic captured yet. Click Start, then use the app (navigate tabs, sign in, etc).</div>';return;}
  l.innerHTML=d.entries.slice().reverse().map(function(e){
    var col=e.direction==='outbound'?'#a78bfa':'#38b6ff';
    var sc=e.status>=400?'#f87171':(e.status>=300?'#fb923c':'#34d399');
    return '<div style="border-bottom:1px solid #111b27;padding:5px 0">'+
      '<span style="color:'+col+'">'+e.direction.toUpperCase()+'</span> '+
      '<span style="color:#e8ff47">'+e.method+'</span> '+
      '<span style="color:'+sc+'">'+(e.status||'')+'</span> '+
      '<span style="color:#4a6685">'+(e.duration_ms||'')+'ms</span><br>'+
      '<span style="color:#d4e4f5;word-break:break-all">'+(e.url||e.path||'')+'</span>'+
      (e.req_body?'<br><span style="color:#4a6685">req:</span> <span style="color:#8aa">'+
        (e.req_body+'').replace(/</g,'&lt;').slice(0,300)+'</span>':'')+
      '</div>';
  }).join('');
}
async function capRefreshList(){
  const l=document.getElementById('cap-list');
  if(!l || l.style.display==='none') return;
  try{const r=await fetch('/__capture/view');const d=await r.json();capRenderList(d);}catch(e){}
}
async function capView(){
  const l=document.getElementById('cap-list');
  if(l.style.display!=='none'){l.style.display='none';return;}
  l.style.display='block';
  await capRefreshList();
}
// Poll status always; refresh the open list every interval so new traffic
// appears live without needing to close and reopen the panel.
setInterval(function(){capPoll();capRefreshList();},1200);capPoll();
</script>
</body>
</html>"""


_MFA_TMPL = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>IDP-Playground -- Verify Identity</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;700&family=Outfit:wght@400;700;800&display=swap" rel="stylesheet">
<style>
:root{--bg:#05080d;--bg2:#090e16;--bg3:#0e1620;--b2:1px solid #1f3349;--ds:#38b6ff;--fs:#a78bfa;--v:#e8ff47;--green:#34d399;--red:#f87171;--orange:#fb923c;--text:#d4e4f5;--muted:#4a6685;}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Outfit',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;}
.box{background:var(--bg2);border:var(--b2);border-radius:14px;padding:28px;width:100%;max-width:460px;box-shadow:0 0 50px rgba(167,139,250,.08);}
.top{text-align:center;margin-bottom:18px;}
.icon{font-size:36px;margin-bottom:6px;}
.t{font-size:17px;font-weight:900;color:#fff;}
.s{font-family:'IBM Plex Mono',monospace;font-size:9px;color:var(--muted);letter-spacing:2px;margin-top:2px;}
.uchip{display:inline-flex;padding:3px 11px;border-radius:20px;background:rgba(56,182,255,.08);border:var(--b2);font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--ds);margin-top:6px;}
.tabs{display:flex;border:var(--b2);border-radius:9px;overflow:hidden;margin-bottom:16px;}
.tab{flex:1;padding:8px 4px;font-family:'Outfit',sans-serif;font-weight:700;font-size:11px;cursor:pointer;border:none;background:var(--bg3);color:var(--muted);transition:all .18s;text-align:center;line-height:1.3;}
.tab.on{background:var(--fs);color:#000;}
.tab:not(:last-child){border-right:var(--b2);}
.pane{display:none;}.pane.on{display:block;}
.info{background:rgba(167,139,250,.06);border:1px solid rgba(167,139,250,.2);border-radius:8px;padding:10px 13px;font-size:12px;color:var(--muted);line-height:1.7;margin-bottom:13px;}
.info strong{color:var(--fs);}
.dev{background:rgba(232,255,71,.06);border:1px solid rgba(232,255,71,.2);border-radius:8px;padding:11px 13px;font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--v);margin-bottom:13px;line-height:1.8;}
.code-inp{width:100%;background:var(--bg);border:var(--b2);border-radius:8px;padding:12px;color:var(--text);font-family:'IBM Plex Mono',monospace;font-size:22px;letter-spacing:8px;text-align:center;outline:none;margin-bottom:11px;}
.code-inp:focus{border-color:var(--fs);}
.btn{width:100%;padding:11px;border-radius:9px;font-family:'Outfit',sans-serif;font-weight:700;font-size:14px;cursor:pointer;border:none;transition:all .18s;margin-bottom:7px;}
.btn-fs{background:var(--fs);color:#000;}
.btn-green{background:rgba(52,211,153,.15);color:var(--green);border:1px solid rgba(52,211,153,.3);}
.btn-green:hover{background:rgba(52,211,153,.25);}
.btn-orange{background:rgba(251,146,60,.15);color:var(--orange);border:1px solid rgba(251,146,60,.3);}
.btn-orange:hover{background:rgba(251,146,60,.25);}
.btn-ghost{background:transparent;color:var(--muted);border:var(--b2);}
.btn-ghost:hover{border-color:var(--ds);color:var(--ds);}
.btn-sm{width:auto;padding:7px 14px;font-size:12px;}
.btn:disabled{opacity:.4;cursor:not-allowed;}
.drop{display:block;width:100%;box-sizing:border-box;border:1px dashed #1f3349;border-radius:9px;padding:20px 14px;text-align:center;cursor:pointer;transition:all .18s;margin-bottom:11px;}
.drop:hover,.drop.over{border-color:var(--green);background:rgba(52,211,153,.04);}
.drop input{display:none;}
.drop-icon{font-size:28px;margin-bottom:5px;}
.drop-lbl{font-weight:700;font-size:13px;margin-bottom:3px;}
.drop-sub{font-size:11px;color:var(--muted);}
.cert-ok{font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--green);padding:7px 11px;background:rgba(52,211,153,.06);border:1px solid rgba(52,211,153,.2);border-radius:7px;margin-bottom:11px;display:none;}
.pk-status{font-family:'IBM Plex Mono',monospace;font-size:11px;padding:9px 12px;border-radius:7px;margin-bottom:11px;display:none;line-height:1.7;}
.pk-status.ok{background:rgba(52,211,153,.06);border:1px solid rgba(52,211,153,.2);color:var(--green);}
.pk-status.err{background:rgba(248,113,113,.06);border:1px solid rgba(248,113,113,.2);color:var(--red);}
.err{background:rgba(248,113,113,.08);border:1px solid rgba(248,113,113,.2);border-radius:7px;padding:8px 11px;font-size:12px;color:var(--red);margin-bottom:11px;}
.back{text-align:center;margin-top:11px;font-size:12px;color:var(--muted);}
.back a{color:var(--ds);text-decoration:none;}
.hint{margin-top:9px;font-size:11px;color:var(--muted);text-align:center;line-height:1.6;}
.hint a{color:var(--ds);text-decoration:none;}
</style>
</head>
<body>
<div class="box">
 <div class="top">
  <div class="icon">&#x1F510;</div>
  <div class="t">Verify Your Identity</div>
  <div class="s">MULTI-FACTOR AUTHENTICATION</div>
  <div class="uchip">{{ user_name }}</div>
 </div>
 {% if error %}<div class="err">{{ error }}</div>{% endif %}
 <div class="tabs" id="auth-tabs">
  {% if allow_otp %}
  <div class="tab {% if method != 'cert' and method != 'passkey' %}on{% endif %}" onclick="show('otp',this)">
   {% if method == 'totp' %}&#x1F510; Auth Code{% elif method == 'email' %}&#x1F4E7; Email Code{% else %}&#x1F510; Code{% endif %}
  </div>
  {% endif %}
  {% if allow_cba %}
  <div class="tab {% if method == 'cert' %}on{% endif %}" onclick="show('cert',this)">&#x1FAA2; Certificate</div>
  {% endif %}
  {% if allow_passkey %}
  <div class="tab {% if method == 'passkey' %}on{% endif %}" onclick="show('passkey',this)">&#x1F511; Passkey</div>
  {% endif %}
 </div>
 <!-- OTP pane -->
 {% if allow_otp %}
 <div class="pane {% if method != 'cert' and method != 'passkey' %}on{% endif %}" id="pane-otp">
  {% if method == 'totp' %}
  <div class="info">Open your <strong>authenticator app</strong> and enter the 6-digit code for <strong>IDP-Playground</strong>.</div>
  {% else %}
  <div class="info">
   {% if smtp_sent %}Code sent to <strong>{{ email }}</strong>.
   {% else %}<strong>Dev mode:</strong> SMTP not configured.{% endif %}
  </div>
  {% if dev_code %}
  <div class="dev">OTP Code:<br><span style="font-size:26px;letter-spacing:8px;font-weight:700">{{ dev_code }}</span></div>
  {% endif %}
  {% endif %}
  <form method="POST" action="/mfa">
   <input class="code-inp" name="code" type="text" inputmode="numeric" pattern="[0-9]*" maxlength="6" placeholder="------" {% if method != 'cert' and method != 'passkey' %}autofocus{% endif %} autocomplete="one-time-code">
   <button class="btn btn-fs" type="submit">Verify &amp; Sign In</button>
  </form>
  {% if method == 'email' %}
  <form method="POST" action="/mfa/resend"><button class="btn btn-ghost btn-sm" type="submit">Resend Code</button></form>
  {% endif %}
 </div>
 {% endif %}
 <!-- Certificate pane -->
 {% if allow_cba %}
 <div class="pane {% if method == 'cert' %}on{% endif %}" id="pane-cert">
  <div class="info">
   Sign in with your <strong>IDP-Playground client certificate</strong>.<br>
   Get it from <strong>IDP-Playground &#x2192; IDP-DS &#x2192; Users &#x2192; MFA &#x2192; Certificate tab</strong>.
  </div>
  <form id="cf" method="POST" action="/mfa/cert" enctype="multipart/form-data">
   <label class="drop" id="dz" for="cfile"
     ondragover="this.classList.add('over');event.preventDefault()"
     ondragleave="this.classList.remove('over')"
     ondrop="this.classList.remove('over');hd(event)">
    <input type="file" id="cfile" name="cert_file" accept=".cer,.pem,.crt,.p12">
    <div class="drop-icon">&#x1F4C4;</div>
    <div class="drop-lbl">Drop certificate here or click to browse</div>
    <div class="drop-sub">.cer .pem .crt .p12 accepted</div>
   </label>
   <div class="cert-ok" id="cok"></div>
   <button class="btn btn-green" type="submit" id="cbtn" disabled>&#x1FAA2; Verify Certificate &amp; Sign In</button>
  </form>
  <div class="hint">No certificate? <a href="http://localhost:8080" target="_blank">Generate one in IDP-Playground</a> &#x2192; IDP-DS &#x2192; Users &#x2192; MFA</div>
 </div>
 {% endif %}
 <!-- Passkey pane -->
 {% if allow_passkey %}
 <div class="pane {% if method == 'passkey' %}on{% endif %}" id="pane-passkey">
  <div class="info">
   Enter your <strong>Passkey PIN</strong> to sign in.<br>
   This is the simple PIN you set in IDP-Playground — no hardware key needed.
  </div>
  <form method="POST" action="/mfa/passkey-pin">
   <input class="code-inp" name="pin" type="password" inputmode="numeric" pattern="[0-9]*"
     maxlength="4" placeholder="----" autocomplete="off" autofocus
     style="letter-spacing:14px;font-size:26px;text-align:center">
   <button class="btn btn-orange" type="submit">&#x1F511; Sign In with PIN</button>
  </form>

  <div style="display:flex;align-items:center;gap:8px;margin:16px 0 12px">
   <div style="flex:1;height:1px;background:#1f3349"></div>
   <span style="font-size:10px;color:#4a6685;font-family:'IBM Plex Mono',monospace">OR USE A SECURITY KEY / BIOMETRIC</span>
   <div style="flex:1;height:1px;background:#1f3349"></div>
  </div>
  <div class="pk-status" id="pk-status"></div>
  <button class="btn btn-ghost" id="pk-btn" onclick="startPasskey('{{ user_id }}')">Use Windows Hello / Security Key</button>
  <form id="pk-form" method="POST" action="/mfa/passkey" style="display:none">
   <input type="hidden" name="credential_id" id="pk-cred-id">
  </form>

  <div class="hint">
   First time? <a href="http://localhost:8080" target="_blank">Set your PIN in IDP-Playground</a><br>
   &#x2192; IDP-DS &#x2192; Users &#x2192; Enable MFA &#x2192; Passkey &#x2192; 4-digit PIN
  </div>
 </div>
 {% endif %}
 <div class="back"><a href="/logout">Cancel</a></div>
</div>
<script>
var _uid = "{{ user_id }}";
function show(p,el){
 document.querySelectorAll('.tab').forEach(t=>t.classList.remove('on'));
 document.querySelectorAll('.pane').forEach(x=>x.classList.remove('on'));
 el.classList.add('on');
 var pane=document.getElementById('pane-'+p);
 if(pane)pane.classList.add('on');
}
// Certificate file handling
function sf(f){
 if(!f)return;
 var ok=document.getElementById('cok');
 ok.textContent='\u2713 '+f.name;
 ok.style.display='block';
 document.getElementById('cbtn').disabled=false;
 var lbl=document.querySelector('.drop .drop-lbl');
 if(lbl) lbl.textContent=f.name;
}
var cinput=document.getElementById('cfile');
if(cinput) cinput.addEventListener('change',function(){sf(this.files[0]);});
function hd(e){
 e.preventDefault();
 var f=e.dataTransfer.files[0];
 if(f){
  // Assign the dropped file to the real file input so the form submits it
  try{
   var dt=new DataTransfer();
   dt.items.add(f);
   cinput.files=dt.files;
  }catch(err){/* older browsers: change listener still covers click-to-browse */}
  sf(f);
 }
}
// Guard: block submit if no file actually attached to the input
var certForm=document.getElementById('cf');
if(certForm){
 certForm.addEventListener('submit',function(e){
  if(!cinput.files||!cinput.files.length){
   e.preventDefault();
   var ok=document.getElementById('cok');
   ok.textContent='Please select a certificate file first';
   ok.style.display='block';
  }
 });
}
// Passkey WebAuthn flow
async function startPasskey(uid){
 var btn=document.getElementById('pk-btn');
 var status=document.getElementById('pk-status');
 btn.disabled=true;
 status.className='pk-status ok';
 status.style.display='block';
 status.textContent='Requesting passkey options from server...';
 try {
  // Get auth options from server
  var resp=await fetch('/passkey/auth-options/'+uid,{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
  var opts=await resp.json();
  if(opts.error){throw new Error(opts.error);}
  // Convert challenge and credential IDs to ArrayBuffers
  opts.challenge=b64ToAb(opts.challenge);
  if(opts.allowCredentials){
   opts.allowCredentials=opts.allowCredentials.map(function(c){
    return {type:c.type,id:b64ToAb(c.id)};
   });
  }
  status.textContent='Waiting for your authenticator...';
  // Trigger browser passkey prompt
  var cred=await navigator.credentials.get({publicKey:opts});
  status.textContent='Passkey verified — completing sign-in...';
  // Send credential ID to server
  document.getElementById('pk-cred-id').value=cred.id;
  document.getElementById('pk-form').submit();
 } catch(e){
  status.className='pk-status err';
  status.textContent='Passkey error: '+e.message;
  btn.disabled=false;
 }
}
function b64ToAb(b64){
 var pad=b64.replace(/-/g,'+').replace(/_/g,'/');
 while(pad.length%4)pad+='=';
 var bin=atob(pad);
 var buf=new Uint8Array(bin.length);
 for(var i=0;i<bin.length;i++)buf[i]=bin.charCodeAt(i);
 return buf.buffer;
}
</script>

<div id="cap-panel" style="position:fixed;bottom:16px;right:16px;z-index:9000;font-family:'Outfit',sans-serif">
  <div id="cap-bar" style="display:flex;align-items:center;gap:8px;background:#0e1620;border:1px solid #1f3349;border-radius:10px;padding:8px 12px;box-shadow:0 8px 30px rgba(0,0,0,.5)">
    <span id="cap-dot" style="width:9px;height:9px;border-radius:50%;background:#4a6685;display:inline-block"></span>
    <span style="font-size:11px;font-weight:700;color:#d4e4f5;font-family:'IBM Plex Mono',monospace">TRAFFIC CAPTURE</span>
    <span id="cap-count" style="font-size:10px;color:#4a6685;font-family:'IBM Plex Mono',monospace">0</span>
    <button id="cap-toggle" onclick="capToggle()" style="border:none;border-radius:7px;padding:6px 12px;font-weight:700;font-size:12px;cursor:pointer;background:#34d399;color:#000">Start</button>
    <button onclick="capDownload()" style="border:1px solid #1f3349;border-radius:7px;padding:6px 10px;font-size:12px;cursor:pointer;background:transparent;color:#4a6685">Download</button>
    <button onclick="capView()" style="border:1px solid #1f3349;border-radius:7px;padding:6px 10px;font-size:12px;cursor:pointer;background:transparent;color:#4a6685">View</button>
    <button onclick="capClear()" style="border:1px solid #1f3349;border-radius:7px;padding:6px 10px;font-size:12px;cursor:pointer;background:transparent;color:#f87171">Clear</button>
  </div>
  <div id="cap-list" style="display:none;margin-top:8px;width:560px;max-height:340px;overflow:auto;background:#05080d;border:1px solid #1f3349;border-radius:10px;padding:10px;font-family:'IBM Plex Mono',monospace;font-size:10px;color:#d4e4f5"></div>
</div>
<script>
let _capActive=false;
async function capToggle(){
  const ep=_capActive?'/__capture/stop':'/__capture/start';
  const r=await fetch(ep,{method:'POST'});const d=await r.json();
  _capActive=d.active;capRender();
}
function capRender(){
  document.getElementById('cap-dot').style.background=_capActive?'#f87171':'#4a6685';
  const b=document.getElementById('cap-toggle');
  b.textContent=_capActive?'Stop':'Start';
  b.style.background=_capActive?'#f87171':'#34d399';
  b.style.color=_capActive?'#fff':'#000';
}
async function capPoll(){
  try{const r=await fetch('/__capture/status');const d=await r.json();
    _capActive=d.active;document.getElementById('cap-count').textContent=d.count;capRender();}catch(e){}
}
function capDownload(){
  const a=document.createElement('a');a.href='/__capture/download';
  a.download='idp-playground-traffic.json';a.click();
}
async function capClear(){await fetch('/__capture/clear',{method:'POST'});capPoll();
  document.getElementById('cap-list').style.display='none';}
function capRenderList(d){
  const l=document.getElementById('cap-list');
  if(!l) return;
  if(!d.entries.length){l.innerHTML='<div style="color:#4a6685">No traffic captured yet. Click Start, then use the app (navigate tabs, sign in, etc).</div>';return;}
  l.innerHTML=d.entries.slice().reverse().map(function(e){
    var col=e.direction==='outbound'?'#a78bfa':'#38b6ff';
    var sc=e.status>=400?'#f87171':(e.status>=300?'#fb923c':'#34d399');
    return '<div style="border-bottom:1px solid #111b27;padding:5px 0">'+
      '<span style="color:'+col+'">'+e.direction.toUpperCase()+'</span> '+
      '<span style="color:#e8ff47">'+e.method+'</span> '+
      '<span style="color:'+sc+'">'+(e.status||'')+'</span> '+
      '<span style="color:#4a6685">'+(e.duration_ms||'')+'ms</span><br>'+
      '<span style="color:#d4e4f5;word-break:break-all">'+(e.url||e.path||'')+'</span>'+
      (e.req_body?'<br><span style="color:#4a6685">req:</span> <span style="color:#8aa">'+
        (e.req_body+'').replace(/</g,'&lt;').slice(0,300)+'</span>':'')+
      '</div>';
  }).join('');
}
async function capRefreshList(){
  const l=document.getElementById('cap-list');
  if(!l || l.style.display==='none') return;
  try{const r=await fetch('/__capture/view');const d=await r.json();capRenderList(d);}catch(e){}
}
async function capView(){
  const l=document.getElementById('cap-list');
  if(l.style.display!=='none'){l.style.display='none';return;}
  l.style.display='block';
  await capRefreshList();
}
// Poll status always; refresh the open list every interval so new traffic
// appears live without needing to close and reopen the panel.
setInterval(function(){capPoll();capRefreshList();},1200);capPoll();
</script>
</body>
</html>"""


# ── Routes ────────────────────────────────────────────────

def _extract_cert_fingerprint(cert_bytes):
    """
    Extract a SHA-256 fingerprint from an uploaded certificate in ANY common
    format: PEM (.cer/.pem/.crt), DER (binary .cer), or PKCS#12 (.p12/.pfx,
    including password-protected). Returns (fingerprint_hex, None) on success
    or (None, error_message) on failure. The error message includes a short
    diagnostic of what was actually received so problems are easy to pin down.
    """
    import base64 as _b64
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import hashes as _hh
    from cryptography.hazmat.backends import default_backend as _ddb
    from cryptography.hazmat.primitives.serialization import pkcs12 as _p12

    if not cert_bytes:
        return None, "file was empty"

    errors = []

    def _fp(c):
        return c.fingerprint(_hh.SHA256()).hex()

    # ---- 1. PEM: pull out the CERTIFICATE block specifically. A file may hold
    #         a key + cert (combined PEM); we only want the certificate.
    if b"-----BEGIN" in cert_bytes:
        try:
            # Find the CERTIFICATE armor block(s)
            import re as _re
            blocks = _re.findall(
                rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                cert_bytes, _re.DOTALL)
            if blocks:
                c = _x509.load_pem_x509_certificate(blocks[0], _ddb())
                return _fp(c), None
            # No explicit CERTIFICATE block — try whole thing as PEM cert
            c = _x509.load_pem_x509_certificate(cert_bytes, _ddb())
            return _fp(c), None
        except Exception as e:
            errors.append(f"PEM:{e}")

    # ---- 2. PKCS#12: try no-password first, then common defaults.
    for pw in (None, b"", b"idp-playground", b"changeit", b"password"):
        try:
            _k, _c, _chain = _p12.load_key_and_certificates(cert_bytes, pw, _ddb())
            if _c is not None:
                return _fp(_c), None
        except Exception as e:
            errors.append(f"PKCS12({pw}):{type(e).__name__}")
            # Keep trying other passwords
            continue

    # ---- 3. Bare DER certificate.
    try:
        c = _x509.load_der_x509_certificate(cert_bytes, _ddb())
        return _fp(c), None
    except Exception as e:
        errors.append(f"DER:{type(e).__name__}")

    # ---- 4. Maybe base64 text WITHOUT PEM armor (just the body).
    try:
        compact = b"".join(cert_bytes.split())
        der = _b64.b64decode(compact, validate=False)
        c = _x509.load_der_x509_certificate(der, _ddb())
        return _fp(c), None
    except Exception as e:
        errors.append(f"B64:{type(e).__name__}")

    # ---- Diagnostic: show what we actually got so the user/dev can tell.
    head = cert_bytes[:16]
    if head[:1] == b"<":
        diag = "file looks like HTML (the download may have failed or returned a login page)"
    elif head[:10].isascii() and head[:5] == b"-----":
        diag = "PEM armor present but no valid CERTIFICATE block found"
    else:
        diag = f"first bytes={head!r}"
    return None, (f"unrecognized certificate ({diag}). "
                  "Supported: .cer .pem .crt .p12 — re-download from IDP-Playground "
                  "(IDP-DS, Users, MFA, Certificate)")


def _complete_login(user_rec, our_app):
    """
    Finalize login: request a signed token from IDP-Playground and store the session.
    Applies impersonation swap (admin acting as a target user) if one was set,
    adding an RFC 8693 actor (act) claim. Fully guarded so a token-issue failure
    never produces a 500 — the user is still logged in locally with whatever
    token (or none) we could obtain.
    """
    try:
        target_id    = session.pop("_impersonate_target_id", None)
        impersonator = session.pop("_impersonator", None)
        subject_user = user_rec or {}
        extra_claims = {}

        if target_id and impersonator:
            try:
                tr = requests.get(f"{IDPPLAYGROUND_BASE}/api/ds/users",
                                  params={"q": ""}, timeout=4).json()
                tgt = next((u for u in tr if u.get("id") == target_id), None)
            except Exception:
                tgt = None
            if tgt:
                subject_user = tgt
                extra_claims["act"] = {"sub": impersonator.get("upn"),
                                       "name": impersonator.get("name", impersonator.get("upn"))}

        app_id  = (our_app or {}).get("id") if isinstance(our_app, dict) else _our_app_id
        subject = subject_user.get("upn", "")
        token   = ""
        if app_id and subject:
            try:
                issue = requests.post(f"{IDPPLAYGROUND_BASE}/api/fs/tokens/issue", json={
                    "app_id":   app_id,
                    "subject":  subject,
                    "lifetime": 3600,
                    "scopes":   "openid profile email groups",
                    "extra_claims": extra_claims,
                }, timeout=5).json()
                token = issue.get("token", "") or ""
            except Exception:
                token = ""

        session["user"]  = subject_user
        session["token"] = token
        session.modified = True
        return redirect(url_for("index"))
    except Exception:
        # Even on unexpected failure, log the user in locally so they aren't stuck.
        try:
            session["user"]  = user_rec or {}
            session["token"] = ""
            session.modified = True
        except Exception:
            pass
        return redirect(url_for("index"))


@client.route("/")
def index():
    connected = _get_or_register()
    user      = session.get("user")
    token     = session.get("token")
    claims    = {}
    decoded   = ""
    exp_str   = ""
    if token:
        claims  = _decode_payload(token)
        decoded = json.dumps(claims, indent=2)
        if claims.get("exp"):
            exp_str = datetime.datetime.fromtimestamp(
                claims["exp"]).strftime("%Y-%m-%d %H:%M:%S")
    return render_template_string(
        _TMPL,
        connected=connected, user=user, token=token or "",
        claims=claims, decoded=decoded, exp_str=exp_str,
    )


@client.route("/login")
def login():
    return render_template_string(_LOGIN_TMPL, error=request.args.get("error", ""), build=BUILD_VERSION)


@client.route("/auth", methods=["POST"])
def auth():
    """Step 1 — validate credentials, then check if MFA is required."""
    if not _get_or_register():
        return redirect(url_for("index"))

    upn      = request.form.get("upn", "").strip()
    password = request.form.get("password", "")

    # 1. Look up user in IDP-DS
    try:
        r     = requests.get(f"{IDPPLAYGROUND_BASE}/api/ds/users", params={"q": upn}, timeout=4)
        users = r.json()
    except Exception:
        return redirect(url_for("login") + "?error=IDP-Playground+unreachable")

    user_rec = next(
        (u for u in users if
         u["upn"].lower() == upn.lower() or u["email"].lower() == upn.lower()),
        None,
    )

    if not user_rec:
        return redirect(url_for("login") + "?error=Invalid+credentials")
    if not user_rec.get("enabled", True):
        return redirect(url_for("login") + "?error=Account+is+disabled")
    if user_rec.get("locked", False):
        return redirect(url_for("login") + "?error=Account+is+locked")

    # 1b. Impersonation — admin signs on behalf of another user.
    impersonate = request.form.get("impersonate", "").strip()
    if impersonate:
        admin_groups = {g.get("name") if isinstance(g, dict) else g
                        for g in user_rec.get("groups", [])}
        is_admin = (user_rec.get("sam_account") == "administrator"
                    or "Domain Admins" in admin_groups
                    or "Administrators" in admin_groups)
        if not is_admin:
            return redirect(url_for("login") +
                "?error=Only+administrators+may+sign+on+behalf+of+another+user")
        try:
            tr = requests.get(f"{IDPPLAYGROUND_BASE}/api/ds/users",
                              params={"q": impersonate}, timeout=4).json()
        except Exception:
            return redirect(url_for("login") + "?error=IDP-Playground+unreachable")
        target = next((u for u in tr if
                       u["upn"].lower() == impersonate.lower()
                       or (u.get("email","").lower() == impersonate.lower())), None)
        if not target:
            return redirect(url_for("login") +
                f"?error=Impersonation+target+not+found")
        if not target.get("enabled", True):
            return redirect(url_for("login") +
                "?error=Impersonation+target+account+is+disabled")
        # Record actor, proceed as the target. Secondary auth (below) applies to
        # the ADMIN, so keep the admin as user_rec until the challenge resolves.
        session["_impersonator"] = {"upn": user_rec["upn"],
                                    "name": user_rec.get("display_name", user_rec["upn"])}
        session["_impersonate_target_id"] = target["id"]

    # 2. Get the registered app record (cached in _our_app_id)
    global _our_app_id
    our_app = None
    try:
        app_list = requests.get(f"{IDPPLAYGROUND_BASE}/api/fs/applications", timeout=4).json()
        our_app  = next((a for a in app_list if a["name"] == "OIDC Test Client"), None)
        if our_app and not _our_app_id:
            _our_app_id = our_app.get("id")
    except Exception:
        pass

    app_id           = our_app.get("id") if our_app else _our_app_id
    app_requires_mfa = our_app.get("require_mfa", False) if our_app else False
    allow_auth       = our_app.get("allow_authenticator", False) if our_app else False
    allow_email      = our_app.get("allow_email", False) if our_app else False
    allow_sms        = our_app.get("allow_sms", False) if our_app else False
    allow_push       = our_app.get("allow_push", False) if our_app else False
    allow_cba        = our_app.get("allow_cba", False) if our_app else False
    allow_passkey    = our_app.get("allow_passkey", False) if our_app else False

    # ── App-authoritative MFA policy ──────────────────────────────
    # The application decides whether MFA is required and which methods it
    # accepts. If the app does not require MFA, login is password-only. If it
    # does require MFA, only methods enabled on the app AND enrolled by the user
    # are offered. Authenticator/Email/SMS/Push are all 6-digit code methods.
    if not app_requires_mfa:
        return _complete_login(user_rec, our_app)

    user_has_cert = user_has_passkey_cred = False
    try:
        st = requests.get(
            f"{IDPPLAYGROUND_BASE}/api/ds/users/{user_rec['id']}/mfa/status", timeout=4)
        if st.ok:
            sj = st.json()
            user_has_cert         = bool(sj.get("has_cert"))
            user_has_passkey_cred = bool(sj.get("has_webauthn") or sj.get("has_pin"))
    except Exception:
        pass

    # The user's code-based method is usable only if the app enables that channel
    code_flag = {"totp": allow_auth, "email": allow_email,
                 "sms": allow_sms, "push": allow_push}
    umethod = user_rec.get("mfa_method", "totp")
    user_has_code = user_rec.get("mfa_enabled", False) and umethod in code_flag
    show_otp     = bool(user_has_code) and code_flag.get(umethod, False)
    show_cert    = allow_cba     and user_has_cert
    show_passkey = allow_passkey and user_has_passkey_cred
    if not (allow_auth or allow_email or allow_sms or allow_push or allow_cba or allow_passkey):
        return redirect(url_for("login") +
            "?error=This+app+requires+MFA+but+no+method+is+enabled+for+it.")
    if not (show_otp or show_cert or show_passkey):
        return redirect(url_for("login") +
            "?error=This+app+requires+MFA+but+your+account+has+none+of+its+enabled+methods.")

    allow_cba     = show_cert
    allow_passkey = show_passkey
    user_has_otp  = show_otp
    challenge_needed = True

    if challenge_needed:
        if user_has_otp:
            try:
                mfa_resp = requests.post(
                    f"{IDPPLAYGROUND_BASE}/api/ds/users/{user_rec['id']}/mfa/check",
                    json={"app_id": app_id}, timeout=4).json()
            except Exception as exc:
                return redirect(url_for("login") + f"?error=MFA+check+failed:+{exc}")
            session["mfa_method"]    = mfa_resp.get("method", "totp") or "totp"
            session["mfa_email"]     = mfa_resp.get("email", "")
            session["mfa_smtp_sent"] = mfa_resp.get("smtp_sent", False)
            session["mfa_dev_code"]  = mfa_resp.get("dev_code")
        else:
            session["mfa_method"]    = "cert" if allow_cba else "passkey"
            session["mfa_email"]     = ""
            session["mfa_smtp_sent"] = False
            session["mfa_dev_code"]  = None
        session["mfa_otp_available"] = user_has_otp
        # Effective (user OR app) availability so the challenge page shows the
        # right tabs even when only the user has the credential.
        session["mfa_allow_cba"]     = allow_cba
        session["mfa_allow_passkey"] = allow_passkey
        session["pending_user"] = user_rec
        session["pending_app"]  = our_app
        session["mfa_app_id"]   = app_id
        session.modified = True
        return redirect(url_for("mfa_challenge"))

    return _complete_login(user_rec, our_app)


@client.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@client.route("/api/me")
def api_me():
    user  = session.get("user")
    token = session.get("token")
    if not user or not token:
        return jsonify({"authenticated": False}), 401
    return jsonify({
        "authenticated": True,
        "user":   user,
        "token":  token,
        "claims": _decode_payload(token),
    })


@client.route("/api/section/<name>")
def api_section(name):
    """
    Backing data for each navigation tab. Each tab fetches its section from
    here, so moving around the app generates real HTTP traffic that the capture
    panel records. Some sections also call back to IDP-Playground, producing captured
    HTTPS traffic (useful for troubleshooting claims and auth).
    """
    user  = session.get("user")
    token = session.get("token")
    if not user or not token:
        return jsonify({"error": "not authenticated"}), 401
    claims = _decode_payload(token)

    if name == "dashboard":
        return jsonify({
            "section": "dashboard",
            "session_active": True,
            "token_expires": claims.get("exp"),
            "auth_method": user.get("mfa_method") if user.get("mfa_enabled") else "password",
            "group_count": len(claims.get("groups", [])),
        })

    if name == "profile":
        # Refetch the live user record from IDP-Playground -> captured HTTPS call
        live = {}
        try:
            r = requests.get(f"{IDPPLAYGROUND_BASE}/api/ds/users",
                             params={"q": user.get("upn", "")}, timeout=4)
            rows = r.json()
            live = next((u for u in rows if u.get("upn") == user.get("upn")), {})
        except Exception as e:
            live = {"error": str(e)}
        return jsonify({"section": "profile", "session_user": user, "live_directory": live})

    if name == "token":
        return jsonify({"section": "token", "raw_token": token, "claims": claims})

    if name == "groups":
        return jsonify({"section": "groups", "groups": claims.get("groups", [])})

    if name == "settings":
        return jsonify({
            "section": "settings",
            "client": "OIDC Test Client",
            "redirect_uri": REDIRECT_URI,
            "scopes": SCOPES,
            "idp": IDPPLAYGROUND_BASE,
        })

    return jsonify({"error": f"unknown section: {name}"}), 404


# ── Entry point ───────────────────────────────────────────

# ─── MFA / CBA / Passkey routes ───────────────────────────
@client.route("/mfa", methods=["GET"])
def mfa_challenge():
    if not session.get("pending_user"):
        return redirect(url_for("login"))
    pu = session.get("pending_user", {})
    pa = session.get("pending_app") or {}
    # Prefer the effective flags computed at login (user OR app credential);
    # fall back to the app record for older sessions.
    allow_cba     = session.get("mfa_allow_cba",
                        bool(pa.get("allow_cba", False)) if isinstance(pa, dict) else False)
    allow_passkey = session.get("mfa_allow_passkey",
                        bool(pa.get("allow_passkey", False)) if isinstance(pa, dict) else False)
    allow_otp     = session.get("mfa_otp_available", True)
    return render_template_string(
        _MFA_TMPL,
        method      = session.get("mfa_method", "totp"),
        email       = session.get("mfa_email", ""),
        smtp_sent   = session.get("mfa_smtp_sent", False),
        dev_code    = session.get("mfa_dev_code"),
        error       = request.args.get("error", ""),
        user_name   = pu.get("display_name", ""),
        user_id     = pu.get("id", ""),
        allow_cba     = allow_cba,
        allow_passkey = allow_passkey,
        allow_otp     = allow_otp,
    )

@client.route("/mfa", methods=["POST"])
def mfa_verify():
    """
    Verify the submitted Auth Code (TOTP or email OTP) and complete login.
    The entire body is wrapped so any unexpected error renders a readable
    diagnostic page instead of a blank 500.
    """
    try:
        if not session.get("pending_user"):
            return redirect(url_for("login") + "?error=Session+expired.+Sign+in+again.")
        code     = request.form.get("code", "").strip()
        user_rec = session.get("pending_user") or {}
        uid      = user_rec.get("id")
        if not code:
            return redirect(url_for("mfa_challenge") + "?error=Please+enter+the+code")
        if not uid:
            session.clear()
            return redirect(url_for("login") + "?error=Session+is+missing+a+user.+Sign+in+again.")

        payload = {"code": code}
        app_id  = session.get("mfa_app_id")
        if app_id:
            payload["app_id"] = app_id

        try:
            resp = requests.post(
                f"{IDPPLAYGROUND_BASE}/api/ds/users/{uid}/mfa/check",
                json=payload, timeout=5)
        except requests.exceptions.RequestException as exc:
            return redirect(url_for("mfa_challenge") +
                f"?error=Cannot+reach+IDP-Playground:+{exc}")

        if resp.status_code == 404:
            session.clear()
            return redirect(url_for("login") +
                "?error=Your+session+is+stale+(user+not+found).+Please+sign+in+again.")
        if resp.status_code >= 500:
            return redirect(url_for("mfa_challenge") +
                "?error=IDP-Playground+server+error.+Try+again.")

        try:
            verify = resp.json()
        except Exception:
            return redirect(url_for("mfa_challenge") +
                "?error=Unexpected+response+from+IDP-Playground.+Try+again.")

        if not verify.get("verified"):
            return redirect(url_for("mfa_challenge") +
                "?error=Invalid+or+expired+code.+Try+again.")

        our_app = session.get("pending_app")
        for k in ["pending_user","pending_app","mfa_method","mfa_email",
                  "mfa_smtp_sent","mfa_dev_code","mfa_app_id","mfa_otp_available",
                  "mfa_allow_cba","mfa_allow_passkey"]:
            session.pop(k, None)
        session.modified = True
        return _complete_login(user_rec, our_app)

    except Exception as e:
        import traceback
        return (
            "<html><body style='background:#0b0f1a;color:#e6edf3;font-family:monospace;padding:30px'>"
            "<h1 style='color:#f87171'>Auth code verification error</h1>"
            "<pre style='background:#11161f;border:1px solid #1f3349;border-radius:8px;padding:16px;white-space:pre-wrap'>"
            + traceback.format_exc() +
            "</pre><p><a style='color:#38b6ff' href='/login'>Back to login</a></p></body></html>", 500)

@client.route("/mfa/cert", methods=["POST"])
def mfa_cert():
    """
    Certificate-based login. Forwards the uploaded certificate file straight to
    IDP-Playground, which parses it with its own robust parser and matches it against
    the user's stored certificate. The client does no certificate parsing at all,
    so format quirks can never break the client.
    """
    try:
        if not session.get("pending_user"):
            return redirect(url_for("login") + "?error=Session+expired.+Sign+in+again.")
        user_rec  = session.get("pending_user") or {}
        uid       = user_rec.get("id")
        cert_file = request.files.get("cert_file")
        if not cert_file or not (cert_file.filename or "").strip():
            return redirect(url_for("mfa_challenge") + "?error=No+certificate+file+selected")
        cert_bytes = cert_file.read()
        if not cert_bytes:
            return redirect(url_for("mfa_challenge") + "?error=Certificate+file+is+empty")
        if not uid:
            session.clear()
            return redirect(url_for("login") + "?error=Session+missing+user.+Sign+in+again.")

        try:
            resp = requests.post(
                f"{IDPPLAYGROUND_BASE}/api/ds/users/{uid}/mfa/verify-cert",
                files={"cert_file": (cert_file.filename, cert_bytes)},
                timeout=8)
        except requests.exceptions.RequestException as exc:
            return redirect(url_for("mfa_challenge") + f"?error=Cannot+reach+IDP-Playground:+{exc}")

        try:
            data = resp.json()
        except Exception:
            return redirect(url_for("mfa_challenge") +
                "?error=Unexpected+response+from+IDP-Playground")

        if not data.get("verified"):
            msg = data.get("error", "Certificate not recognized or revoked")
            return redirect(url_for("mfa_challenge") +
                "?error=" + requests.utils.quote(str(msg)))

        our_app = session.get("pending_app")
        for k in ["pending_user","pending_app","mfa_method","mfa_email",
                  "mfa_smtp_sent","mfa_dev_code","mfa_app_id","mfa_otp_available",
                  "mfa_allow_cba","mfa_allow_passkey"]:
            session.pop(k, None)
        session.modified = True
        return _complete_login(user_rec, our_app)
    except Exception:
        import traceback
        return (
            "<html><body style='background:#0b0f1a;color:#e6edf3;font-family:monospace;padding:30px'>"
            "<h1 style='color:#f87171'>Certificate login error</h1>"
            "<pre style='background:#11161f;border:1px solid #1f3349;border-radius:8px;padding:16px;white-space:pre-wrap'>"
            + traceback.format_exc() +
            "</pre><p><a style='color:#38b6ff' href='/login'>Back to login</a></p></body></html>", 500)

@client.route("/mfa/resend", methods=["POST"])
def mfa_resend():
    user_rec = session.get("pending_user")
    if not user_rec: return redirect(url_for("login"))
    try:
        payload = {}
        app_id = session.get("mfa_app_id")
        if app_id: payload["app_id"] = app_id
        r = requests.post(f"{IDPPLAYGROUND_BASE}/api/ds/users/{user_rec['id']}/mfa/check",
                          json=payload, timeout=4).json()
        session["mfa_smtp_sent"] = r.get("smtp_sent", False)
        session["mfa_dev_code"]  = r.get("dev_code")
        session.modified = True
    except Exception: pass
    return redirect(url_for("mfa_challenge"))

@client.route("/passkey/auth-options/<uid>", methods=["POST"])
def passkey_auth_options_proxy(uid):
    try:
        r = requests.post(f"{IDPPLAYGROUND_BASE}/api/ds/users/{uid}/passkey/auth-options",
                          json={}, timeout=4)
        return r.text, r.status_code, {"Content-Type": "application/json"}
    except Exception as e:
        return '{"error":"' + str(e) + '"}', 500, {"Content-Type": "application/json"}

@client.route("/mfa/passkey", methods=["POST"])
def mfa_passkey():
    if not session.get("pending_user"):
        return redirect(url_for("login"))
    user_rec = session["pending_user"]
    cred_id  = request.form.get("credential_id", "").strip()
    if not cred_id:
        return redirect(url_for("mfa_challenge") + "?error=No+passkey+credential+received")
    try:
        verify = requests.post(
            f"{IDPPLAYGROUND_BASE}/api/ds/users/{user_rec['id']}/passkey/auth-complete",
            json={"id": cred_id}, timeout=4).json()
    except Exception as exc:
        return redirect(url_for("mfa_challenge") + f"?error=Passkey+error:+{exc}")
    if not verify.get("verified"):
        return redirect(url_for("mfa_challenge") + "?error=Passkey+not+recognized.+Register+in+IDP-Playground+first.")
    our_app = session.get("pending_app")
    for k in ["pending_user","pending_app","mfa_method","mfa_email",
              "mfa_smtp_sent","mfa_dev_code","mfa_app_id"]:
        session.pop(k, None)
    session.modified = True
    return _complete_login(user_rec, our_app)


@client.route("/mfa/passkey-pin", methods=["POST"])
def mfa_passkey_pin():
    if not session.get("pending_user"):
        return redirect(url_for("login"))
    user_rec = session["pending_user"]
    pin = request.form.get("pin", "").strip()
    if not pin:
        return redirect(url_for("mfa_challenge") + "?error=Please+enter+your+PIN")
    try:
        verify = requests.post(
            f"{IDPPLAYGROUND_BASE}/api/ds/users/{user_rec['id']}/passkey/verify-pin",
            json={"pin": pin}, timeout=4).json()
    except Exception as exc:
        return redirect(url_for("mfa_challenge") + f"?error=PIN+error:+{exc}")
    if not verify.get("verified"):
        return redirect(url_for("mfa_challenge") + "?error=Incorrect+PIN.+Try+again.")
    our_app = session.get("pending_app")
    for k in ["pending_user","pending_app","mfa_method","mfa_email",
              "mfa_smtp_sent","mfa_dev_code","mfa_app_id"]:
        session.pop(k, None)
    session.modified = True
    return _complete_login(user_rec, our_app)
# ══════════════════════════════════════════════════════════════════════════
import time as _cap_time
import threading as _cap_threading

_CAP = {
    "active": False,
    "entries": [],
    "lock": _cap_threading.Lock(),
    "started_at": None,
}
_CAP_MAX = 5000  # cap entries to avoid unbounded memory

def _cap_add(entry):
    with _CAP["lock"]:
        if not _CAP["active"]:
            return
        _CAP["entries"].append(entry)
        if len(_CAP["entries"]) > _CAP_MAX:
            _CAP["entries"] = _CAP["entries"][-_CAP_MAX:]

# ---- Capture inbound HTTP traffic to this client app ----
@client.before_request
def _cap_before():
    if not _CAP["active"]:
        return
    try:
        request._cap_start = _cap_time.time()
    except Exception:
        pass

@client.after_request
def _cap_after(response):
    if not _CAP["active"]:
        return response
    try:
        if request.path.startswith("/__capture"):
            return response
        dur = None
        if hasattr(request, "_cap_start"):
            dur = round((_cap_time.time() - request._cap_start) * 1000, 1)
        body_preview = ""
        try:
            if request.method in ("POST", "PUT", "PATCH"):
                raw = request.get_data(cache=True) or b""
                body_preview = raw[:2000].decode("utf-8", "replace")
        except Exception:
            body_preview = "<unreadable>"
        _cap_add({
            "ts": _cap_time.strftime("%Y-%m-%d %H:%M:%S"),
            "direction": "inbound",
            "scheme": request.scheme,
            "method": request.method,
            "url": request.url,
            "path": request.path,
            "status": response.status_code,
            "duration_ms": dur,
            "req_headers": {k: v for k, v in request.headers.items()},
            "req_body": body_preview,
            "resp_headers": {k: v for k, v in response.headers.items()},
            "resp_content_type": response.headers.get("Content-Type", ""),
        })
    except Exception:
        pass
    return response

# ---- Capture outbound HTTPS/HTTP traffic to IDP-Playground (requests lib) ----
_orig_request_fn = requests.sessions.Session.request
def _cap_request(self, method, url, **kwargs):
    start = _cap_time.time()
    resp = _orig_request_fn(self, method, url, **kwargs)
    if _CAP["active"]:
        try:
            req_body = kwargs.get("json") or kwargs.get("data") or ""
            if not isinstance(req_body, str):
                try:
                    req_body = json.dumps(req_body)[:2000]
                except Exception:
                    req_body = str(req_body)[:2000]
            resp_preview = ""
            try:
                resp_preview = resp.text[:2000]
            except Exception:
                resp_preview = "<unreadable>"
            _cap_add({
                "ts": _cap_time.strftime("%Y-%m-%d %H:%M:%S"),
                "direction": "outbound",
                "scheme": url.split(":", 1)[0],
                "method": method.upper(),
                "url": url,
                "path": url,
                "status": resp.status_code,
                "duration_ms": round((_cap_time.time() - start) * 1000, 1),
                "req_headers": dict(kwargs.get("headers") or {}),
                "req_body": req_body,
                "resp_headers": dict(resp.headers),
                "resp_content_type": resp.headers.get("Content-Type", ""),
                "resp_body": resp_preview,
            })
        except Exception:
            pass
    return resp
requests.sessions.Session.request = _cap_request

@client.route("/__capture/start", methods=["POST"])
def _cap_start_route():
    with _CAP["lock"]:
        _CAP["active"] = True
        _CAP["entries"] = []
        _CAP["started_at"] = _cap_time.strftime("%Y-%m-%d %H:%M:%S")
    return jsonify({"ok": True, "active": True, "started_at": _CAP["started_at"]})

@client.route("/__capture/stop", methods=["POST"])
def _cap_stop_route():
    with _CAP["lock"]:
        _CAP["active"] = False
        count = len(_CAP["entries"])
    return jsonify({"ok": True, "active": False, "count": count})

@client.route("/__capture/status", methods=["GET"])
def _cap_status_route():
    with _CAP["lock"]:
        return jsonify({
            "active": _CAP["active"],
            "count": len(_CAP["entries"]),
            "started_at": _CAP["started_at"],
        })

@client.route("/__capture/clear", methods=["POST"])
def _cap_clear_route():
    with _CAP["lock"]:
        _CAP["entries"] = []
    return jsonify({"ok": True})

@client.route("/__capture/download", methods=["GET"])
def _cap_download_route():
    with _CAP["lock"]:
        data = {
            "captured_by": "IDP-Playground Test Client",
            "started_at": _CAP["started_at"],
            "exported_at": _cap_time.strftime("%Y-%m-%d %H:%M:%S"),
            "entry_count": len(_CAP["entries"]),
            "entries": list(_CAP["entries"]),
        }
    payload = json.dumps(data, indent=2)
    fname = "idp-playground-traffic-" + _cap_time.strftime("%Y%m%d-%H%M%S") + ".json"
    return payload, 200, {
        "Content-Type": "application/json",
        "Content-Disposition": f"attachment; filename={fname}",
    }

@client.route("/__capture/view", methods=["GET"])
def _cap_view_route():
    with _CAP["lock"]:
        entries = list(_CAP["entries"])[-200:]
    return jsonify({"entries": entries, "active": _CAP["active"]})


if __name__ == "__main__":
    PORT = 5000

    # Strip every Werkzeug env var before starting.
    # When launched as a subprocess of IDP-Playground, the parent's debug server
    # leaves WERKZEUG_SERVER_FD in the environment which causes WinError 10038.
    for _v in ("WERKZEUG_SERVER_FD", "WERKZEUG_RUN_MAIN", "SERVER_NAME",
               "WERKZEUG_SERVER_FD", "PYTHONHTTPSVERIFY"):
        os.environ.pop(_v, None)

    print(f"  IDP-Playground OIDC Test Client  ->  http://localhost:{PORT}", flush=True)
    print(f"  Requires IDP-Playground           ->  http://localhost:8080",    flush=True)

    # Use Python's built-in wsgiref WSGI server.
    # No reloader, no socket FD passing, no Werkzeug debug — runs cleanly
    # as a subprocess on Windows and Linux alike.
    httpd = make_server("0.0.0.0", PORT, client.wsgi_app, handler_class=_QuietHandler)
    print(f"  Serving on port {PORT} …", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("  Stopped.", flush=True)
    finally:
        httpd.server_close()
