# IDP-Playground Identity Platform — all-in-one demo image
# Builds a single image that runs the IDP-Playground server plus the four protocol
# test clients (OIDC, SAML, OAuth2, WS-Fed) under a small supervisor.
#
# Build:  docker build -t idp-playground:latest -f docker/Dockerfile .
# Run:    docker run --rm -p 8080:8080 -p 5000:5000 -p 5001:5001 \
#                 -p 5002:5002 -p 5003:5003 idp-playground:latest
#
# Then open http://localhost:8080 (admin) and the clients on 5000-5003.

FROM python:3.12-slim AS base

# Avoid interactive prompts, keep Python output unbuffered for live logs
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# System deps:
#  - libffi / build tools are only needed if a wheel is unavailable; slim images
#    usually have wheels for cryptography/bcrypt, but we add the minimum to be safe.
#  - cloudflared provides the optional Cloudflare named-tunnel for public access.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && ARCH="$(dpkg --print-architecture)" \
    && case "$ARCH" in \
         amd64) CF_ARCH=amd64 ;; \
         arm64) CF_ARCH=arm64 ;; \
         *)     CF_ARCH=amd64 ;; \
       esac \
    && curl -fsSL -o /usr/local/bin/cloudflared \
         "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${CF_ARCH}" \
    && chmod +x /usr/local/bin/cloudflared \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first for better layer caching
COPY docker/requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

# Copy the application
COPY idp_playground_server.py /app/idp_playground_server.py
COPY templates /app/templates
COPY test_apps /app/test_apps
COPY docker/start.py /app/start.py

# The instance/ directory holds the SQLite DB; it is created at runtime.
# Mounting a volume here persists the directory across container restarts.
RUN mkdir -p /app/instance
VOLUME ["/app/instance"]

# Clients reach the server over the shared container network namespace.
# In a single container, localhost works for both server-to-server calls and
# the browser (because the same ports are published to the host).
ENV IDPPLAYGROUND_BASE=http://localhost:8080 \
    RUN_CLIENTS=1 \
    SERVER_PORT=8080 \
    TUNNEL_ENABLED=0 \
    TUNNEL_CONFIG=/etc/cloudflared/config.yml

# Cloudflare tunnel config + credentials are mounted here at runtime (public mode)
RUN mkdir -p /etc/cloudflared

# Admin (8080) + OIDC (5000) + SAML (5001) + OAuth2 (5002) + WS-Fed (5003)
EXPOSE 8080 5000 5001 5002 5003

# Simple healthcheck against the server's version endpoint
HEALTHCHECK --interval=30s --timeout=4s --start-period=15s --retries=3 \
    CMD curl -fsS http://localhost:8080/api/ds/stats || exit 1

# Run as non-root for safety. The instance dir must be writable by this user.
RUN useradd --create-home --uid 10001 idp-playground \
    && chown -R idp-playground:idp-playground /app
USER idp-playground

CMD ["python", "/app/start.py"]
