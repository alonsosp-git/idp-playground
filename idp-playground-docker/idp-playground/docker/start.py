#!/usr/bin/env python3
"""
IDP-Playground container entrypoint.

Launches the IDP-Playground identity server plus the four protocol test clients
(OIDC, SAML, OAuth2, WS-Fed) as child processes inside a single container and
supervises them. If any process exits, all are torn down so the container stops
and your orchestrator (Docker, compose, k8s) can restart it cleanly.

Two run modes:

  LOCAL (default)
    All five services share the container's network namespace, so each client
    reaches the server at http://localhost:8080, and the same URL works from
    your host browser because the ports are published. Nothing else needed.

  PUBLIC via Cloudflare named tunnel  (TUNNEL_ENABLED=1)
    A cloudflared process is started alongside the apps. It connects out to
    Cloudflare and serves your services on stable public HTTPS hostnames like
    https://idp.example.com (8080), https://oidc.example.com (5000), etc.
    You supply the tunnel credentials and a config that maps hostnames to local
    ports (see docker/cloudflared/config.example.yml). In this mode you should
    also set IDPPLAYGROUND_BASE and the *_PUBLIC_URL vars to the public hostnames so
    browser redirects resolve correctly (the compose file does this for you).

Environment variables (all optional):
  IDPPLAYGROUND_BASE     Base URL the clients use to reach the server.
                     LOCAL default http://localhost:8080.
                     PUBLIC: set to your IdP hostname, e.g. https://idp.example.com
  OIDC_PUBLIC_URL    Public base URL of each client, used for its callback/ACS.
  SAML_PUBLIC_URL    Default to the localhost port in LOCAL mode.
  OAUTH2_PUBLIC_URL
  WSFED_PUBLIC_URL
  RUN_CLIENTS        "1" (default) to start the test clients, "0" for server only.
  SERVER_PORT        Server port (default 8080).
  TUNNEL_ENABLED     "1" to start the Cloudflare tunnel, "0" (default) for local.
  TUNNEL_CONFIG      Path to cloudflared config (default /etc/cloudflared/config.yml).
  TUNNEL_TOKEN       Alternatively, a Cloudflare tunnel token. If set, cloudflared
                     runs token-based and TUNNEL_CONFIG is ignored.
"""
import os
import sys
import signal
import subprocess
import time

ROOT = "/app"

SERVER_PORT     = os.environ.get("SERVER_PORT", "8080")
RUN_CLIENTS     = os.environ.get("RUN_CLIENTS", "1") == "1"
TUNNEL_ENABLED  = os.environ.get("TUNNEL_ENABLED", "0") == "1"
TUNNEL_CONFIG   = os.environ.get("TUNNEL_CONFIG", "/etc/cloudflared/config.yml")
TUNNEL_TOKEN    = os.environ.get("TUNNEL_TOKEN", "").strip()

# Each entry: (label, working_dir, script, port)
SERVICES = [
    ("idp-playground-server", ROOT, "idp_playground_server.py", SERVER_PORT),
]
if RUN_CLIENTS:
    SERVICES += [
        ("oidc-client",   f"{ROOT}/test_apps/oidc_client",   "testclient_oidc.py",   "5000"),
        ("saml-client",   f"{ROOT}/test_apps/saml_client",   "testclient_saml.py",   "5001"),
        ("oauth2-client", f"{ROOT}/test_apps/oauth2_client", "testclient_oauth2.py", "5002"),
        ("wsfed-client",  f"{ROOT}/test_apps/wsfed_client",  "testclient_wsfed.py",  "5003"),
    ]

procs = []


def log(msg):
    print(f"[supervisor] {msg}", flush=True)


def launch(label, cwd, script, port):
    env = dict(os.environ)
    # Clean Werkzeug subprocess env vars that can confuse child servers
    for v in ("WERKZEUG_SERVER_FD", "WERKZEUG_RUN_MAIN"):
        env.pop(v, None)
    log(f"starting {label} ({script}) on port {port}")
    p = subprocess.Popen([sys.executable, script], cwd=cwd, env=env)
    return p


def launch_tunnel():
    """Start the Cloudflare tunnel. Supports either a token (TUNNEL_TOKEN) or a
    config file (TUNNEL_CONFIG) that maps hostnames to local ports."""
    if TUNNEL_TOKEN:
        log("starting cloudflared (token mode)")
        cmd = ["cloudflared", "tunnel", "--no-autoupdate", "run",
               "--token", TUNNEL_TOKEN]
    else:
        if not os.path.exists(TUNNEL_CONFIG):
            log(f"TUNNEL_ENABLED=1 but config not found at {TUNNEL_CONFIG}")
            log("Provide docker/cloudflared/config.yml + credentials, or set TUNNEL_TOKEN.")
            return None
        log(f"starting cloudflared (config mode: {TUNNEL_CONFIG})")
        cmd = ["cloudflared", "tunnel", "--no-autoupdate",
               "--config", TUNNEL_CONFIG, "run"]
    try:
        return subprocess.Popen(cmd)
    except FileNotFoundError:
        log("cloudflared binary not found in image; cannot start tunnel")
        return None


def shutdown(*_):
    log("shutting down all services ...")
    for label, p in procs:
        if p.poll() is None:
            try:
                p.terminate()
            except Exception:
                pass
    # Give them a moment, then hard-kill
    deadline = time.time() + 5
    for label, p in procs:
        while p.poll() is None and time.time() < deadline:
            time.sleep(0.1)
        if p.poll() is None:
            try:
                p.kill()
            except Exception:
                pass
    sys.exit(0)


def main():
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    # Start the server first, then give it a head start so clients can register.
    for i, (label, cwd, script, port) in enumerate(SERVICES):
        p = launch(label, cwd, script, port)
        procs.append((label, p))
        if i == 0:
            time.sleep(3)   # let the server bind and seed its database

    log("all services started")
    log("  IDP-Playground admin : http://localhost:%s" % SERVER_PORT)
    if RUN_CLIENTS:
        log("  OIDC client     : http://localhost:5000")
        log("  SAML client     : http://localhost:5001")
        log("  OAuth2 client   : http://localhost:5002")
        log("  WS-Fed client   : http://localhost:5003")

    # Optionally start the Cloudflare named tunnel for public access.
    if TUNNEL_ENABLED:
        tp = launch_tunnel()
        if tp is not None:
            procs.append(("cloudflared", tp))
            log("Cloudflare tunnel started — your services are reachable on the")
            log("public hostnames configured in your tunnel (e.g. https://idp.example.com).")
        else:
            log("tunnel was requested but could not start; continuing local-only")
    else:
        log("LOCAL mode (set TUNNEL_ENABLED=1 to expose via Cloudflare tunnel)")

    # Supervise: if any process dies, tear everything down.
    try:
        while True:
            for label, p in procs:
                code = p.poll()
                if code is not None:
                    log(f"{label} exited with code {code}; stopping container")
                    shutdown()
            time.sleep(1)
    except KeyboardInterrupt:
        shutdown()


if __name__ == "__main__":
    main()
