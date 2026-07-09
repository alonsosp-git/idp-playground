# -*- coding: utf-8 -*-
"""
IDP-Playground -- WS-Federation Demo Client
File : testclient_wsfed.py   Port: 5003

WS-Federation passive requestor profile:
  1. Client redirects to IDP-Playground with wa=wsignin1.0
  2. IDP-Playground issues a WS-Fed token (JWT wrapped in RSTR)
  3. Client parses the token and establishes session

Run: python testclient_wsfed.py
"""

import os, sys, io, json, secrets, base64, datetime
from wsgiref.simple_server import make_server, WSGIRequestHandler
from urllib.parse import urlencode
import requests
from flask import (Flask, render_template_string, request,
                   redirect, url_for, session, jsonify)

if sys.stdout.encoding and sys.stdout.encoding.upper() not in ("UTF-8","UTF8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

IDPPLAYGROUND_BASE = os.environ.get("IDPPLAYGROUND_BASE", "http://localhost:8080")
PUBLIC_URL     = os.environ.get("WSFED_PUBLIC_URL", "http://localhost:5003")
REALM          = PUBLIC_URL + "/"
REPLY_URL      = PUBLIC_URL + "/wsfed/callback"
IDP_WSFED_URL  = f"{IDPPLAYGROUND_BASE}/wsfed"
PORT           = 5003

app = Flask(__name__)
app.secret_key = "idp-playground-wsfed-client-fixed-session-key-2024"
# Unique cookie name so the four localhost demo apps don't overwrite each
# other's session cookie (cookies are shared across ports on the same host).
app.config["SESSION_COOKIE_NAME"] = "va_wsfed_session"

BUILD_VERSION = "2026-06-11-rebrand-dropzone-18"


@app.route("/version")
def _version():
    return {"build": BUILD_VERSION, "protocol": "WS-Fed"}


@app.errorhandler(Exception)
def _show_error(e):
    from werkzeug.exceptions import HTTPException
    import traceback as _tb
    code = e.code if isinstance(e, HTTPException) else 500
    html = ("<html><body style='background:#0b0f1a;color:#e6edf3;font-family:monospace;padding:30px'>"
        "<h1 style='color:#f87171'>WS-Fed client error (" + str(code) + ")</h1>"
        "<pre style='background:#11161f;border:1px solid #1f3349;border-radius:8px;padding:16px;white-space:pre-wrap'>"
        + _tb.format_exc() +
        "</pre><p><a style='color:#38b6ff' href='/'>Back to start</a> &middot; "
        "<a style='color:#38b6ff' href='/logout'>Logout</a></p></body></html>")
    return html, code



def _register():
    try:
        apps = requests.get(f"{IDPPLAYGROUND_BASE}/api/fs/applications", timeout=4).json()
        if any(a["name"] == "WS-Fed Demo App" for a in apps):
            return True
        requests.post(f"{IDPPLAYGROUND_BASE}/api/fs/applications", json={
            "name": "WS-Fed Demo App", "protocol": "WS-Fed",
            "redirect_uris": REPLY_URL,
            "allowed_scopes": "openid profile email groups",
            "icon_emoji": "🏢", "brand_color": "#fb923c",
        }, timeout=4)
        print("  [IDP-Playground] WS-Fed RP registered", flush=True)
        return True
    except Exception as e:
        print(f"  [IDP-Playground] Cannot connect: {e}", flush=True)
        return False


def _connected():
    try:
        requests.get(f"{IDPPLAYGROUND_BASE}/api/ds/stats", timeout=2)
        return True
    except Exception:
        return False


def _decode(token):
    try:
        p = token.split(".")[1]
        p += "=" * ((4-len(p)%4)%4)
        return json.loads(base64.urlsafe_b64decode(p))
    except Exception:
        return {}


_CSS = """<style>
:root{--bg:#05080d;--bg2:#090e16;--bg3:#0e1620;--b:1px solid #172333;--b2:1px solid #1f3349;
  --p:#fb923c;--green:#34d399;--red:#f87171;--v:#e8ff47;--text:#d4e4f5;--muted:#4a6685;}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Outfit',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;padding:32px 20px;}
.wrap{max-width:860px;margin:0 auto;}
.hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;
  padding-bottom:16px;border-bottom:var(--b);flex-wrap:wrap;gap:10px;}
.logo{display:flex;align-items:center;gap:10px;}
.hex{width:36px;height:36px;background:var(--p);
  clip-path:polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%);
  display:flex;align-items:center;justify-content:center;font-size:16px;
  box-shadow:0 0 18px rgba(251,146,60,.4);}
.logo-name{font-size:16px;font-weight:900;color:#fff;}
.logo-sub{font-family:'IBM Plex Mono',monospace;font-size:8px;color:var(--muted);letter-spacing:2px;}
.badge{display:flex;align-items:center;gap:5px;border-radius:20px;padding:4px 11px;
  font-family:'IBM Plex Mono',monospace;font-size:9px;}
.badge::before{content:'';width:5px;height:5px;border-radius:50%;}
.badge-ok{background:rgba(52,211,153,.08);border:var(--b2);color:var(--green);}
.badge-ok::before{background:var(--green);box-shadow:0 0 5px var(--green);}
.badge-p{background:rgba(251,146,60,.1);border:1px solid rgba(251,146,60,.25);color:var(--p);}
.card{background:var(--bg2);border:1px solid rgba(251,146,60,.15);border-radius:11px;overflow:hidden;margin-bottom:14px;}
.ch{display:flex;align-items:center;justify-content:space-between;padding:13px 18px;border-bottom:var(--b);}
.ct{font-size:14px;font-weight:700;}
.cb{padding:18px;}
.btn{display:inline-flex;align-items:center;gap:6px;padding:9px 18px;border-radius:8px;
  font-family:'Outfit',sans-serif;font-weight:700;font-size:13px;cursor:pointer;
  border:none;text-decoration:none;transition:all .18s;}
.btn-p{background:var(--p);color:#000;box-shadow:0 0 14px rgba(251,146,60,.3);}
.btn-p:hover{box-shadow:0 0 26px rgba(251,146,60,.5);transform:translateY(-1px);}
.btn-ghost{background:transparent;color:var(--muted);border:var(--b2);}
.btn-ghost:hover{border-color:var(--p);color:var(--p);}
.btn-red{background:rgba(248,113,113,.1);color:var(--red);border:1px solid rgba(248,113,113,.25);}
.mr{display:flex;justify-content:space-between;align-items:flex-start;padding:8px 0;
  border-bottom:1px solid rgba(23,35,51,.5);font-size:12px;gap:12px;}
.mr:last-child{border-bottom:none;}
.mk{font-family:'IBM Plex Mono',monospace;font-size:9px;color:var(--muted);flex-shrink:0;padding-top:2px;}
.mv{text-align:right;word-break:break-all;font-size:11px;}
.tbox{background:var(--bg);border:var(--b);border-radius:7px;padding:11px 13px;
  font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--green);
  word-break:break-all;overflow-wrap:anywhere;max-width:100%;line-height:1.7;}
pre.dec{font-family:'IBM Plex Mono',monospace;font-size:10px;background:var(--bg3);border:var(--b);
  border-radius:7px;padding:12px;line-height:1.7;color:var(--green);
  white-space:pre-wrap;word-break:break-all;overflow-wrap:anywhere;max-width:100%;}
.flow{display:flex;align-items:center;gap:5px;flex-wrap:wrap;padding:14px 18px;
  font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);}
.step{background:var(--bg3);border:var(--b2);border-radius:6px;padding:5px 10px;color:var(--text);}
.step.done{border-color:var(--green);color:var(--green);}
.arrow{color:var(--p);}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:14px;}
.err{background:rgba(248,113,113,.08);border:1px solid rgba(248,113,113,.2);border-radius:7px;
  padding:9px 13px;font-size:12px;color:var(--red);margin-bottom:12px;}
.gtag{display:inline-flex;padding:3px 9px;border-radius:6px;font-size:11px;font-weight:700;
  background:rgba(251,146,60,.1);color:var(--p);border:1px solid rgba(251,146,60,.2);margin:2px;}
.sess{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;
  background:rgba(52,211,153,.05);border:1px solid rgba(52,211,153,.15);border-radius:10px;
  padding:12px 18px;margin-bottom:20px;max-width:100%;overflow:hidden;}
.av{flex-shrink:0;}
.av{width:34px;height:34px;border-radius:8px;background:rgba(251,146,60,.2);color:var(--p);
  display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:900;}
.chip{display:inline-flex;padding:3px 9px;border-radius:20px;font-size:10px;font-family:'IBM Plex Mono',monospace;}
.chip-ok{background:rgba(52,211,153,.1);color:var(--green);border:1px solid rgba(52,211,153,.2);}
.chip-p{background:rgba(251,146,60,.1);color:var(--p);border:1px solid rgba(251,146,60,.2);}
::-webkit-scrollbar{width:5px;} ::-webkit-scrollbar-track{background:transparent;}
::-webkit-scrollbar-thumb{background:#1f3349;border-radius:3px;}
.navbtn{background:transparent;border:1px solid transparent;border-radius:8px;padding:8px 14px;font-family:'Outfit',sans-serif;font-weight:700;font-size:12px;color:var(--muted);cursor:pointer;transition:all .15s;}
.navbtn:hover{color:var(--text);background:var(--bg3);}
.navbtn.active{background:rgba(251,146,60,.12);color:var(--p);border-color:rgba(251,146,60,.25);}
</style>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;700&family=Outfit:wght@400;700;800;900&display=swap" rel="stylesheet">"""

_TMPL = _CSS + """
<div class="wrap">
 <div class="hdr">
  <div class="logo">
   <div class="hex">🏢</div>
   <div><div class="logo-name">WS-Federation Demo App</div>
    <div class="logo-sub">WS-FEDERATION -- localhost:5003</div></div>
  </div>
  <div style="display:flex;gap:8px;align-items:center">
   <span class="badge badge-p">WS-Federation</span>
   {% if connected %}<span class="badge badge-ok">IDP-Playground Online</span>{% endif %}
  </div>
 </div>

 <div class="card">
  <div class="ch"><div class="ct">WS-Federation Passive Requestor Flow</div></div>
  <div class="flow">
   <div class="step {% if step>=1 %}done{% endif %}">1. User visits RP</div><span class="arrow">--></span>
   <div class="step {% if step>=2 %}done{% endif %}">2. wa=wsignin1.0</div><span class="arrow">--></span>
   <div class="step {% if step>=3 %}done{% endif %}">3. IDP Auth</div><span class="arrow">--></span>
   <div class="step {% if step>=4 %}done{% endif %}">4. RSTR POST back</div><span class="arrow">--></span>
   <div class="step {% if step>=5 %}done{% endif %}">5. Token parsed</div>
  </div>
 </div>

 {% if not connected %}
 <div class="err">IDP-Playground not reachable at http://localhost:8080 -- start idp_playground_server.py first.</div>
 {% elif token_data %}
 {% set claims = token_data.claims %}
 <div class="sess">
  <div style="display:flex;align-items:center;gap:10px;min-width:0;flex:1">
   <div class="av">{{ (claims.get('name') or claims.get('sub') or 'U')[0]|upper }}</div>
   <div style="min-width:0;overflow:hidden">
    <div style="font-weight:700;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:260px">{{ claims.get('name') or claims.get('sub') or 'User' }}</div>
    <div style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:260px">{{ claims.get('sub','') }}</div>
   </div>
  </div>
  <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
   <span class="chip chip-ok">Token Received</span>
   <span class="chip chip-p">WS-Federation</span>
   <a href="/logout" class="btn btn-red" style="padding:5px 12px;font-size:11px">Sign out</a>
  </div>
 </div>

 <div id="appnav" style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:20px;padding:6px;background:var(--bg2);border:var(--b);border-radius:11px">
  <button class="navbtn active" data-view="overview" onclick="nav('overview')">🏠 Overview</button>
  <button class="navbtn" data-view="token" onclick="nav('token')">🎫 Token</button>
  <button class="navbtn" data-view="claims" onclick="nav('claims')">🏷 Claims</button>
  <button class="navbtn" data-view="groups" onclick="nav('groups')">👥 Groups</button>
  <button class="navbtn" data-view="directory" onclick="nav('directory')">👤 Directory</button>
 </div>

 <div id="view-body"></div>

 {% else %}
 <div class="card" style="max-width:440px;margin:0 auto;text-align:center">
  <div class="cb" style="padding:32px 24px">
   <div style="font-size:48px;margin-bottom:12px">🏢</div>
   <div style="font-size:16px;font-weight:700;margin-bottom:8px">WS-Federation Protected Resource</div>
   <div style="font-size:12px;color:var(--muted);margin-bottom:24px;line-height:1.7">
    Click below to initiate WS-Federation sign-in.<br>
    The browser posts a sign-in request (wsignin1.0) to IDP-Playground.
   </div>
   <a href="/wsfed/login" class="btn btn-p">Initiate WS-Fed Sign-in</a>
   <div style="margin-top:16px;background:rgba(251,146,60,.05);border:1px solid rgba(251,146,60,.15);
     border-radius:8px;padding:12px;font-family:'IBM Plex Mono',monospace;font-size:10px;
     color:var(--muted);text-align:left;line-height:1.8">
    wtrealm: <span style="color:var(--p)">{{ realm }}</span><br>
    wreply:  <span style="color:var(--p)">{{ reply_url }}</span><br>
    IDP URL: <span style="color:var(--p)">{{ idp_url }}</span>
   </div>
  </div>
 </div>
 {% endif %}

<script>
function _esc(s){return String(s==null?'':s).replace(/[&<>]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c];});}
function _row(k,v){return '<div class="mr"><span class="mk">'+_esc(k)+'</span><span class="mv">'+_esc(v)+'</span></div>';}
function _card(t,inner){return '<div class="card"><div class="ch"><div class="ct">'+_esc(t)+'</div></div><div class="cb">'+inner+'</div></div>';}
function _fmt(v){return Array.isArray(v)?v.join(', '):(v&&typeof v==='object'?JSON.stringify(v):v);}
function renderWSFED(view,d){
  if(d && d.error) return _card('Error','<div style="color:var(--red)">'+_esc(d.error)+'</div>');
  if(view==='overview')
    return _card('WS-Federation — Overview',
      _row('Protocol', d.protocol||'WS-Federation')+_row('Subject', d.subject)+
      _row('Group claims', d.group_count)+_row('Token', 'Validated ✓'));
  if(view==='token')
    return _card('Security Token',
      _row('Type','JWT (Bearer)')+_row('Expires', d.expires))+
      _card('Raw Token','<div class="tbox" style="word-break:break-all">'+_esc(d.raw_token||d.token||'')+'</div>')+
      _card('Decoded Claims','<pre class="dec" style="margin:0;white-space:pre-wrap;word-break:break-all">'+_esc(d.decoded||'')+'</pre>');
  if(view==='claims'){
    var a=d.claims||{}; var ks=Object.keys(a);
    var rows=ks.length?ks.map(function(k){return _row(k,_fmt(a[k]));}).join(''):'<div style="color:var(--muted);font-size:12px">No claims in token</div>';
    return _card('Security Token Claims', rows);
  }
  if(view==='groups'){
    var g=d.groups||[];
    return _card('Group Claims', g.length?g.map(function(x){return '<span class="gtag">'+_esc(x)+'</span>';}).join(''):'<div style="color:var(--muted);font-size:12px">No group claims</div>');
  }
  if(view==='directory'){
    var u=d.live_directory||{};
    if(u.error) return _card('Directory Lookup','<div style="color:var(--red)">'+_esc(u.error)+'</div>');
    if(!Object.keys(u).length) return _card('Live Directory (from IDP-Playground)','<div style="color:var(--muted);font-size:12px">No directory record found</div>');
    return _card('Live Directory (looked up from IDP-Playground)',
      _row('Display Name',u.display_name)+_row('UPN',u.upn)+_row('Email',u.email)+
      _row('Department',u.department)+_row('Title',u.title)+_row('Enabled',u.enabled));
  }
  return _card(view, '<pre class="dec">'+_esc(JSON.stringify(d,null,2))+'</pre>');
}
async function nav(view){
  document.querySelectorAll('.navbtn').forEach(function(b){ b.classList.toggle('active', b.dataset.view===view); });
  var vb=document.getElementById('view-body');
  var box=document.getElementById('navresult');
  var title=document.getElementById('navresult-title');
  var body=document.getElementById('navresult-body');
  if(vb) vb.innerHTML='<div class="card"><div class="cb" style="color:var(--muted)">Loading '+_esc(view)+'…</div></div>';
  if(title) title.textContent=view.charAt(0).toUpperCase()+view.slice(1)+' — GET /api/section/'+view;
  if(box) box.style.display='block';
  try{
    var r=await fetch('/api/section/'+view);
    var d=await r.json();
    if(vb) vb.innerHTML=renderWSFED(view,d);
    if(body) body.textContent=JSON.stringify(d,null,2);
  }catch(e){ if(vb) vb.innerHTML='<div class="card"><div class="cb" style="color:var(--red)">Error: '+_esc(e.message)+'</div></div>'; }
  window.scrollTo(0,0);
}
window.addEventListener('DOMContentLoaded', function(){
  if(document.getElementById('appnav')){ nav('overview'); }
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
</div>"""

# ── Routes ────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template_string(_TMPL,
        connected=_connected(),
        token_data=session.get("token_data"),
        step=session.get("step", 1),
        realm=REALM, reply_url=REPLY_URL,
        idp_url=IDP_WSFED_URL,
    )


@app.route("/wsfed/login")
def wsfed_login():
    _register()
    wctx = secrets.token_urlsafe(12)
    session["wctx"] = wctx
    session["step"] = 2
    params = urlencode({
        "wa":      "wsignin1.0",
        "wtrealm": REALM,
        "wreply":  REPLY_URL,
        "wctx":    wctx,
    })
    return redirect(f"{IDP_WSFED_URL}?{params}")


@app.route("/wsfed/callback", methods=["GET", "POST"])
def wsfed_callback():
    """Receive the security token from IDP-Playground IDP."""
    # IDP-Playground returns the JWT in wresult parameter
    wresult = request.form.get("wresult", "") or request.args.get("wresult", "")
    if not wresult:
        return redirect(url_for("index") + "?err=no_wresult")

    # Parse the JWT out of the wresult (IDP-Playground returns plain JWT here)
    raw_token = wresult.strip()
    claims    = _decode(raw_token)
    if not claims:
        return redirect(url_for("index") + "?err=invalid_token")

    exp_str = datetime.datetime.fromtimestamp(
        claims.get("exp",0)).strftime("%Y-%m-%d %H:%M:%S") if claims.get("exp") else ""

    session["token_data"] = {
        "raw_token":   raw_token,
        "claims":      claims,
        "decoded":     json.dumps(claims, indent=2),
        "exp_str":     exp_str,
    }
    session["step"] = 5
    return redirect(url_for("index"))


@app.route("/api/section/<name>")
def api_section(name):
    """Section data for nav tabs; generates captured traffic, some to IDP-Playground."""
    td = session.get("token_data")
    if not td:
        return jsonify({"error": "no token in session"}), 401
    claims = td.get("claims", {})
    if name == "overview":
        return jsonify({"section": "overview", "protocol": "WS-Federation",
                        "subject": claims.get("sub"),
                        "group_count": len(claims.get("groups", []))})
    if name == "token":
        return jsonify({"section": "token",
                        "token": td.get("token") or td.get("raw_token"),
                        "raw_token": td.get("raw_token"),
                        "decoded": td.get("decoded"),
                        "expires": td.get("exp_str"),
                        "claims": claims})
    if name == "claims":
        return jsonify({"section": "claims", "claims": claims})
    if name == "groups":
        return jsonify({"section": "groups", "groups": claims.get("groups", [])})
    if name == "directory":
        live = {}
        try:
            sub = claims.get("sub", "")
            r = requests.get(f"{IDPPLAYGROUND_BASE}/api/ds/users", params={"q": sub}, timeout=4)
            rows = r.json()
            live = next((u for u in rows if u.get("upn") == sub or u.get("email") == sub), {})
        except Exception as e:
            live = {"error": str(e)}
        return jsonify({"section": "directory", "live_directory": live})
    return jsonify({"error": f"unknown section: {name}"}), 404


@app.route("/logout")
def logout():
    params = urlencode({"wa": "wsignout1.0", "wtrealm": REALM})
    session.clear()
    return redirect(url_for("index"))


class _Q(WSGIRequestHandler):
    def log_message(self, fmt, *args):
        print(f"  [WS-Fed] {fmt % args}", flush=True)


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
  <div class="tab {% if method != 'cert' and method != 'passkey' %}on{% endif %}" onclick="show('otp',this)">
   {% if method == 'totp' %}&#x1F510; Auth Code{% elif method == 'email' %}&#x1F4E7; Email Code{% else %}&#x1F510; Code{% endif %}
  </div>
  {% if allow_cba %}
  <div class="tab {% if method == 'cert' %}on{% endif %}" onclick="show('cert',this)">&#x1FAA2; Certificate</div>
  {% endif %}
  {% if allow_passkey %}
  <div class="tab {% if method == 'passkey' %}on{% endif %}" onclick="show('passkey',this)">&#x1F511; Passkey</div>
  {% endif %}
 </div>
 <!-- OTP pane -->
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
   Sign in with your <strong>Passkey</strong> (biometric / hardware key).<br>
   Your browser will prompt you to use Face ID, Touch ID, Windows Hello, or a security key.
  </div>
  <div class="pk-status" id="pk-status"></div>
  <button class="btn btn-orange" id="pk-btn" onclick="startPasskey('{{ user_id }}')">&#x1F511; Sign In with Passkey</button>
  <form id="pk-form" method="POST" action="/mfa/passkey" style="display:none">
   <input type="hidden" name="credential_id" id="pk-cred-id">
  </form>
  <div class="hint">
   First time? <a href="http://localhost:8080" target="_blank">Register your passkey in IDP-Playground</a><br>
   &#x2192; IDP-DS &#x2192; Users &#x2192; MFA &#x2192; Passkey tab
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
 ok.textContent='&#x2713; '+f.name;
 ok.style.display='block';
 document.getElementById('cbtn').disabled=false;
 document.querySelector('.drop .drop-lbl').textContent=f.name;
}
var cinput=document.getElementById('cfile');
if(cinput) cinput.addEventListener('change',function(){sf(this.files[0]);});
function hd(e){e.preventDefault();var f=e.dataTransfer.files[0];if(f)sf(f);}
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

# ─── MFA / CBA / Passkey routes ───────────────────────────
@app.route("/mfa", methods=["GET"])
def mfa_challenge():
    if not session.get("pending_user"):
        return redirect(url_for("index"))
    pu = session.get("pending_user", {})
    pa = session.get("pending_app") or {}
    allow_cba     = bool(pa.get("allow_cba",     False)) if isinstance(pa, dict) else False
    allow_passkey = bool(pa.get("allow_passkey", False)) if isinstance(pa, dict) else False
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
    )

@app.route("/mfa", methods=["POST"])
def mfa_verify():
    if not session.get("pending_user"):
        return redirect(url_for("index"))
    code     = request.form.get("code", "").strip()
    user_rec = session["pending_user"]
    if not code:
        return redirect(url_for("mfa_challenge") + "?error=Please+enter+the+code")
    try:
        payload = {"code": code}
        app_id  = session.get("mfa_app_id")
        if app_id: payload["app_id"] = app_id
        verify = requests.post(
            f"{IDPPLAYGROUND_BASE}/api/ds/users/{user_rec['id']}/mfa/check",
            json=payload, timeout=4).json()
    except Exception as exc:
        return redirect(url_for("mfa_challenge") + f"?error=Verification+error:+{exc}")
    if not verify.get("verified"):
        return redirect(url_for("mfa_challenge") + "?error=Invalid+or+expired+code.+Try+again.")
    our_app = session.get("pending_app")
    for k in ["pending_user","pending_app","mfa_method","mfa_email",
              "mfa_smtp_sent","mfa_dev_code","mfa_app_id"]:
        session.pop(k, None)
    session.modified = True
    return redirect(url_for("index"))

@app.route("/mfa/cert", methods=["POST"])
def mfa_cert():
    if not session.get("pending_user"):
        return redirect(url_for("index"))
    user_rec  = session["pending_user"]
    cert_file = request.files.get("cert_file")
    if not cert_file:
        return redirect(url_for("mfa_challenge") + "?error=No+certificate+file+uploaded")
    cert_bytes = cert_file.read()
    try:
        from cryptography import x509 as _x509
        from cryptography.hazmat.primitives import hashes as _hh
        from cryptography.hazmat.backends import default_backend as _ddb
        try:
            cert_obj = _x509.load_pem_x509_certificate(cert_bytes, _ddb())
        except Exception:
            cert_obj = _x509.load_der_x509_certificate(cert_bytes, _ddb())
        fingerprint = cert_obj.fingerprint(_hh.SHA256()).hex()
    except Exception as e:
        return redirect(url_for("mfa_challenge") + f"?error=Invalid+certificate:+{e}")
    try:
        verify = requests.post(
            f"{IDPPLAYGROUND_BASE}/api/ds/users/{user_rec['id']}/mfa/verify-cert",
            json={"fingerprint": fingerprint}, timeout=4).json()
    except Exception as exc:
        return redirect(url_for("mfa_challenge") + f"?error=Cert+verify+error:+{exc}")
    if not verify.get("verified"):
        return redirect(url_for("mfa_challenge") + "?error=Certificate+not+recognized+or+revoked")
    our_app = session.get("pending_app")
    for k in ["pending_user","pending_app","mfa_method","mfa_email",
              "mfa_smtp_sent","mfa_dev_code","mfa_app_id"]:
        session.pop(k, None)
    session.modified = True
    return redirect(url_for("index"))

@app.route("/mfa/resend", methods=["POST"])
def mfa_resend():
    user_rec = session.get("pending_user")
    if not user_rec: return redirect(url_for("index"))
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

@app.route("/passkey/auth-options/<uid>", methods=["POST"])
def passkey_auth_options_proxy(uid):
    try:
        r = requests.post(f"{IDPPLAYGROUND_BASE}/api/ds/users/{uid}/passkey/auth-options",
                          json={}, timeout=4)
        return r.text, r.status_code, {"Content-Type": "application/json"}
    except Exception as e:
        return '{"error":"' + str(e) + '"}', 500, {"Content-Type": "application/json"}

@app.route("/mfa/passkey", methods=["POST"])
def mfa_passkey():
    if not session.get("pending_user"):
        return redirect(url_for("index"))
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
    return redirect(url_for("index"))



# ══════════════════════════════════════════════════════════════════════════
#  Traffic Capture  (Fiddler-style HTTP/HTTPS logging for troubleshooting)
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
@app.before_request
def _cap_before():
    if not _CAP["active"]:
        return
    try:
        request._cap_start = _cap_time.time()
    except Exception:
        pass

@app.after_request
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

@app.route("/__capture/start", methods=["POST"])
def _cap_start_route():
    with _CAP["lock"]:
        _CAP["active"] = True
        _CAP["entries"] = []
        _CAP["started_at"] = _cap_time.strftime("%Y-%m-%d %H:%M:%S")
    return jsonify({"ok": True, "active": True, "started_at": _CAP["started_at"]})

@app.route("/__capture/stop", methods=["POST"])
def _cap_stop_route():
    with _CAP["lock"]:
        _CAP["active"] = False
        count = len(_CAP["entries"])
    return jsonify({"ok": True, "active": False, "count": count})

@app.route("/__capture/status", methods=["GET"])
def _cap_status_route():
    with _CAP["lock"]:
        return jsonify({
            "active": _CAP["active"],
            "count": len(_CAP["entries"]),
            "started_at": _CAP["started_at"],
        })

@app.route("/__capture/clear", methods=["POST"])
def _cap_clear_route():
    with _CAP["lock"]:
        _CAP["entries"] = []
    return jsonify({"ok": True})

@app.route("/__capture/download", methods=["GET"])
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

@app.route("/__capture/view", methods=["GET"])
def _cap_view_route():
    with _CAP["lock"]:
        entries = list(_CAP["entries"])[-200:]
    return jsonify({"entries": entries, "active": _CAP["active"]})


if __name__ == "__main__":
    for v in ("WERKZEUG_SERVER_FD","WERKZEUG_RUN_MAIN","SERVER_NAME"):
        os.environ.pop(v, None)
    _register()
    print(f"  IDP-Playground WS-Fed Demo  ->  http://localhost:{PORT}", flush=True)
    httpd = make_server("0.0.0.0", PORT, app.wsgi_app, handler_class=_Q)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
