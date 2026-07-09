# IDP-Playground in Docker

This packages the entire IDP-Playground Identity Platform — the IdP server plus the
four protocol test clients (OIDC, SAML, OAuth2, WS-Federation) — into a single
container image. Everything runs together under a small supervisor so you can
bring up the whole demo with one command.

## What's inside

| Service            | Port | URL                     |
|--------------------|------|-------------------------|
| IDP-Playground admin/IdP| 8080 | http://localhost:8080   |
| OIDC test client   | 5000 | http://localhost:5000   |
| SAML test client   | 5001 | http://localhost:5001   |
| OAuth2 test client | 5002 | http://localhost:5002   |
| WS-Fed test client | 5003 | http://localhost:5003   |

Default admin login: `administrator@corp.idp-playground.local` / `Admin@IDP-Playground1`

## What each piece is for

IDP-Playground is a self-contained identity platform you can run on your own machine.
It plays the role a company's central login system plays: it stores user
accounts and it issues the security tokens that let those users sign in to other
applications. It has two internal modules, and four small demo applications that
show it working with the major single-sign-on standards.

### The IDP-Playground server (port 8080) — the identity provider

This is the admin console and the engine. It has two parts:

- **IDP-DS — Directory Domain Services.** The directory. This is where user
  accounts, groups, domains, and organizational units live. Think of it as the
  master list of "who exists" in your organization, along with each person's
  attributes (name, email, department) and which groups they belong to. In this
  demo it also stores each user's multi-factor authentication settings and any
  client certificates issued to them.

- **IDP-TS — Token Generator Service.** The token engine. When a user logs in,
  this module produces the signed proof of identity (a token) that an
  application will trust. It speaks the common single-sign-on standards — OIDC,
  SAML 2.0, OAuth 2.0, and WS-Federation — so different kinds of applications
  can all authenticate against the same directory. It also holds the list of
  registered applications (which apps are allowed to ask for tokens) and the
  signing certificate used to prove the tokens are genuine.

Together: IDP-DS knows *who the user is*; IDP-TS *vouches for them* to an
application in whatever token format that application understands.

### The four test applications (ports 5000–5003)

These are small stand-in "business applications" — the kind of app an employee
would log into. Each one is deliberately built around a different single-sign-on
standard so you can see how IDP-Playground serves all of them. None of them store
passwords; they all delegate login to IDP-Playground and simply receive a token back.
Their whole job is to demonstrate and inspect a login, so each one shows you the
exact token it received, decodes it, and (with the built-in traffic capture)
lets you watch the requests fly by.

- **OIDC test client (port 5000).** Uses **OpenID Connect**, the modern login
  standard built on OAuth 2.0 that most new web and mobile apps use (it's what's
  behind many "Sign in with…" buttons). Good first app to try; it has the
  richest built-in navigation to explore the resulting session and token.

- **SAML test client (port 5001).** Uses **SAML 2.0**, the long-established
  enterprise standard still used by a huge number of corporate and SaaS
  applications (HR systems, expense tools, many admin portals). It shows the
  SAML "assertion" — the signed XML statement of who you are — after login.

- **OAuth2 test client (port 5002).** Uses **OAuth 2.0 with PKCE**, the
  authorization-code flow used by single-page and mobile apps to obtain an
  access token securely. It walks you through each step of the exchange
  (generate PKCE, authorize, callback, token) so you can see how an access
  token is obtained.

- **WS-Fed test client (port 5003).** Uses **WS-Federation**, an older standard
  still common in Microsoft-oriented enterprise environments. Included so you can
  confirm the same directory works with legacy federation as well.

Which one should you use? If you just want to see a login work, start with OIDC.
If you're evaluating enterprise SSO, SAML is the most representative. The
walkthrough below uses SAML because its "assertion" makes the result easy to see.

### The traffic capture panel

Every test app has a small **TRAFFIC CAPTURE** panel (Start / Stop / Download /
View / Clear) in the corner. Turn it on before you log in and it records every
request the app makes, including the calls to IDP-Playground. It's there so you can
watch and download the actual login traffic for learning or troubleshooting.

## Quick start (docker compose)

From the project root:

```bash
docker compose -f docker/docker-compose.yml up --build
```

Open http://localhost:8080 for the admin console, and the clients on 5000–5003.
Press Ctrl+C to stop. The SQLite database persists in a named volume between runs.

## Quick start (plain docker)

Build the image (run from the project root so the build context includes the app):

```bash
docker build -t idp-playground:latest -f docker/Dockerfile .
```

Run it, publishing all five ports:

```bash
docker run --rm \
  -p 8080:8080 -p 5000:5000 -p 5001:5001 -p 5002:5002 -p 5003:5003 \
  idp-playground:latest
```

To persist the database across restarts, mount a volume at `/app/instance`:

```bash
docker run --rm \
  -p 8080:8080 -p 5000:5000 -p 5001:5001 -p 5002:5002 -p 5003:5003 \
  -v idp-playground-data:/app/instance \
  idp-playground:latest
```

## Why one container

Each test client redirects your browser to the IdP and also makes server-to-server
API calls to it. Running everything in one container means `http://localhost:8080`
resolves correctly both inside the container (for the API calls) and from your
host browser (because the same ports are published). This avoids the usual
browser-URL-vs-internal-URL split you hit when splitting services across
containers, which keeps the demo simple.

## Tutorial: log in "John Smith" to the SAML app, every which way

This is a complete, click-by-click walkthrough. It uses the pre-created demo
user **John Smith** and the **SAML test app**, and shows you how to set up and
then log in with each of the available authentication methods: password only,
authenticator code, email code, certificate, and passkey PIN. You don't need to
create anything first — the demo user and the SAML app already exist.

Throughout, two web pages are involved:

- The **admin console** at http://localhost:8080 — where you (as an
  administrator) configure the user.
- The **SAML app** at http://localhost:5001 — where "John Smith" logs in.

The demo accounts:

| Account       | Sign-in name                          | Password         |
|---------------|---------------------------------------|------------------|
| Administrator | `administrator@corp.idp-playground.local`  | `Admin@IDP-Playground1` |
| John Smith    | `john.smith@corp.idp-playground.local`     | `Welcome@1`      |

### Part 0 — First, a plain login (password only)

Start here to confirm everything works before adding extra security.

1. Open the SAML app at **http://localhost:5001**.
2. Click **Initiate SAML SSO**. The app hands you off to IDP-Playground to log in.
3. On the IDP-Playground login screen, enter John Smith's sign-in name
   `john.smith@corp.idp-playground.local` and password `Welcome@1`, and continue.
4. You're sent back to the SAML app, now signed in. You'll see the **SAML
   assertion** — the signed statement of who you are — and John Smith's details.

That's a basic single-sign-on login with no second factor. Everything below adds
a second factor (MFA) on top of this.

> Tip: before step 2, click **Start** on the TRAFFIC CAPTURE panel to record the
> whole exchange, then **View** or **Download** it afterward.

### Part 1 — Turn on multi-factor for John Smith (admin side)

Everything in this part happens in the **admin console**, and you only do the
relevant sub-section for the method you want to try. You can set up several
methods for the same user; at login John Smith will pick which one to use.

1. Open **http://localhost:8080** and sign in as the administrator
   (`administrator@corp.idp-playground.local` / `Admin@IDP-Playground1`).
2. In the left menu open **IDP-DS → Users**.
3. Find **John Smith** in the list. In his row, click **Enable MFA** (or
   **Configure MFA** if MFA is already on) to open the setup dialog. The dialog
   shows a legend telling you which methods are already configured.

Now set up whichever method(s) you want:

#### Method A — Authenticator app (6-digit code)

This is the classic "Google/Microsoft Authenticator" code.

1. In the MFA dialog choose **Authenticator App**.
2. A QR code appears. Scan it with any authenticator app (Google Authenticator,
   Microsoft Authenticator, Authy, etc.). The app starts showing a 6-digit code
   that changes every 30 seconds.
3. Type the current 6-digit code into the dialog to confirm, and save.
   John Smith now has authenticator-based MFA.

#### Method B — Email one-time code

Sends a one-time code to the user's email.

1. In the MFA dialog choose **Email OTP**.
2. Confirm the user's email address and save. At login, IDP-Playground will generate
   a one-time code for that address.
   (In this demo, email delivery may be simulated; the code is shown to you so
   you can complete the login without a real mail server. Configure SMTP in the
   server settings if you want real email.)

#### Method C — Certificate (a client certificate file)

The user proves who they are with a certificate file instead of a code.

1. In the MFA dialog choose **Certificate (CBA)**.
2. Click **Generate Certificate for this user**. IDP-Playground creates a certificate
   and downloads it to your computer. **Wait for the download to finish** and
   note where it saved (it will be a real file of roughly 1–4 KB — if you ever
   get a tiny file, generate again).
   You can download it in several formats; a `.cer`/`.pem` or a `.p12` both work.
3. Keep that file handy — John Smith will upload it at login.

#### Method D — Passkey PIN (a 4-digit PIN)

The simplest second factor: a short PIN the user sets, similar to the PIN you'd
set for a web account.

1. In the MFA dialog choose **Passkey (WebAuthn)**.
2. In the passkey section, set a **4-digit PIN** (for example `1234`) and save.
   That PIN is now John Smith's passkey.
   (A hardware security key / Windows Hello option also exists here, but the PIN
   is the easy path and needs no special hardware.)

When you're done, the dialog's legend should show a green "MFA is active" line
listing the methods you configured. Close the dialog.

### Part 2 — Log in to the SAML app with the second factor

Now switch to John Smith's point of view.

1. Open the SAML app at **http://localhost:5001** (use a private/incognito
   window if you're still signed in as admin elsewhere, so the sessions don't
   mix).
2. Click **Initiate SAML SSO**.
3. Enter John Smith's sign-in name and password (`Welcome@1`) as before.
4. Because MFA is now enabled, IDP-Playground shows a **Verify Your Identity** screen
   with tabs for the available methods: **Code**, **Certificate**, and
   **Passkey**. Use the tab that matches what you set up:

   - **Authenticator app (Method A):** on the **Code** tab, open your
     authenticator app, read the current 6-digit code, type it in, and submit.

   - **Email code (Method B):** on the **Code** tab, request/enter the one-time
     code sent to the email (shown on screen in the demo), then submit.

   - **Certificate (Method C):** open the **Certificate** tab. Drag the
     certificate file you downloaded into the drop area (or click to browse and
     select it), then click **Verify Certificate & Sign In**.

   - **Passkey PIN (Method D):** open the **Passkey** tab. Type the 4-digit PIN
     you set (e.g. `1234`) and submit.

5. On success you're returned to the SAML app, fully signed in, and you'll see
   John Smith's SAML assertion and attributes. Use the navigation tabs
   (Overview, Assertion, Attributes, Directory, Metadata) to explore what the
   app received.

That's the full loop: you configured a method on the user in the admin console,
then logged that user into a real application using it. The same pattern works
for the OIDC (5000), OAuth2 (5002), and WS-Fed (5003) apps — only the app you
start from changes; the IDP-Playground login and MFA screens are the same.

### If something doesn't work

- **"Not recognized" on a certificate:** re-download it from the user's MFA
  dialog (make sure the file is a few KB, not tiny) and upload that fresh copy.
- **Code rejected:** authenticator codes are time-based — make sure your device
  clock is accurate and you're entering the current code before it rotates.
- **You see the admin instead of John Smith:** you're still logged in as admin
  in that browser. Use a separate/incognito window for the John Smith login.
- **The MFA tab you want isn't shown:** that method isn't configured for the
  user yet. Go back to Part 1 and set it up, then retry.

## Configuration (environment variables)

| Variable           | Default                  | Purpose                                                     |
|--------------------|--------------------------|-------------------------------------------------------------|
| `IDPPLAYGROUND_BASE`   | `http://localhost:8080`  | Base URL the clients use to reach the IdP (and the browser redirect target). In public mode, set to your IdP hostname, e.g. `https://idp.example.com`. |
| `RUN_CLIENTS`      | `1`                      | `1` runs the four test clients; `0` = server only.          |
| `SERVER_PORT`      | `8080`                   | Port the IdP listens on.                                    |
| `OIDC_PUBLIC_URL`  | `http://localhost:5000`  | Public base URL of the OIDC client (its callback URL).      |
| `SAML_PUBLIC_URL`  | `http://localhost:5001`  | Public base URL of the SAML client (entity ID + ACS URL).   |
| `OAUTH2_PUBLIC_URL`| `http://localhost:5002`  | Public base URL of the OAuth2 client (redirect URI).        |
| `WSFED_PUBLIC_URL` | `http://localhost:5003`  | Public base URL of the WS-Fed client (realm + reply URL).   |
| `TUNNEL_ENABLED`   | `0`                      | `1` starts the Cloudflare named tunnel for public access.   |
| `TUNNEL_CONFIG`    | `/etc/cloudflared/config.yml` | Path (in container) to the cloudflared config.         |
| `TUNNEL_TOKEN`     | _(empty)_                | Alternative to a config file: a Cloudflare tunnel token.    |

### Server only (no test clients)

```bash
docker run --rm -p 8080:8080 -e RUN_CLIENTS=0 idp-playground:latest
```

## Making it public on the internet (Cloudflare named tunnel)

The image can expose all five services on the public internet through a free
Cloudflare named tunnel, giving you stable HTTPS URLs like
`https://idp.example.com` with real TLS — no VM, no open firewall ports, no
public IP. cloudflared runs inside the container and connects outbound to
Cloudflare, which routes your chosen hostnames to the right local port.

### Why the public URLs matter

Each client both redirects your browser to the IdP and makes server-to-server
API calls to it. On `localhost` that "just works", but on the internet
"localhost" is the visitor's own machine. So in public mode you must set
`IDPPLAYGROUND_BASE` and the four `*_PUBLIC_URL` variables to your real hostnames.
The provided `docker-compose.tunnel.yml` does this for you — you only edit the
hostnames in one place.

### One-time Cloudflare setup

You need a domain added to Cloudflare (the free plan is fine). Install
`cloudflared` on your machine for these setup steps (the container has its own
copy for runtime).

1. Authenticate and create the tunnel:

   ```bash
   cloudflared tunnel login
   cloudflared tunnel create idp-playground
   ```

   This prints a tunnel UUID and writes a credentials file
   `~/.cloudflared/<UUID>.json`.

2. Point DNS for each subdomain at the tunnel:

   ```bash
   cloudflared tunnel route dns idp-playground idp.example.com
   cloudflared tunnel route dns idp-playground oidc.example.com
   cloudflared tunnel route dns idp-playground saml.example.com
   cloudflared tunnel route dns idp-playground oauth2.example.com
   cloudflared tunnel route dns idp-playground wsfed.example.com
   ```

3. Prepare the tunnel config for the container:

   ```bash
   mkdir -p docker/cloudflared
   cp docker/cloudflared/config.example.yml docker/cloudflared/config.yml
   cp ~/.cloudflared/<UUID>.json docker/cloudflared/<UUID>.json
   ```

   Edit `docker/cloudflared/config.yml`: set `tunnel:` and
   `credentials-file:` to your `<UUID>`, and replace the `example.com`
   hostnames with yours. (The hostname-to-port mapping is already correct.)

### Run in public mode

Edit the five hostnames near the top of `docker/docker-compose.tunnel.yml` to
match your domain, then:

```bash
docker compose -f docker/docker-compose.tunnel.yml up --build
```

Your services are now live at your public HTTPS hostnames. Note that public mode
does not publish host ports — traffic arrives through the tunnel, not the host.

### Token mode (alternative)

If you create the tunnel in the Cloudflare dashboard instead of the CLI, it
gives you a token. You can skip the config file and just pass the token:

```bash
docker run --rm \
  -e TUNNEL_ENABLED=1 \
  -e TUNNEL_TOKEN=<your-tunnel-token> \
  -e IDPPLAYGROUND_BASE=https://idp.example.com \
  -e OIDC_PUBLIC_URL=https://oidc.example.com \
  -e SAML_PUBLIC_URL=https://saml.example.com \
  -e OAUTH2_PUBLIC_URL=https://oauth2.example.com \
  -e WSFED_PUBLIC_URL=https://wsfed.example.com \
  idp-playground:latest
```

(Configure the hostname-to-service routing in the dashboard tunnel's public
hostnames to match.)

### Security warning for public mode

This is a demo build with default seeded credentials
(`administrator@corp.idp-playground.local` / `Admin@IDP-Playground1`), a development WSGI
server, debug mode, and a local SQLite database. Anyone who reaches the public
URL can log into the admin console. Before exposing it beyond a short, trusted
demo, at minimum change the admin password, and ideally put Cloudflare Access
in front of `idp.example.com` so only authorized people can reach it. Do not
treat this as a production-hardened deployment.

## Health

The image defines a healthcheck against `http://localhost:8080/api/ds/stats`.
`docker ps` will show the container as `healthy` once the IdP is serving.

## Notes and limitations

- This is a demo/development image. It uses Flask's built-in WSGI server and a
  local SQLite database, which are fine for evaluation but not production load.
  For production you would put each service behind a real WSGI server (gunicorn/
  uvicorn) and a reverse proxy, and use a managed database.
- The container runs as a non-root user (`uid 10001`). The mounted
  `/app/instance` volume must be writable by that user; the image sets the right
  ownership at build time, and named volumes inherit it.
- Self-signed certificates and demo secrets are generated at first boot and live
  in the database. Wipe the `idp-playground-data` volume to reseed from scratch.

## Rebuilding after code changes

The Dockerfile copies the application source at build time, so rebuild the image
after editing any `.py` or template:

```bash
docker compose -f docker/docker-compose.yml up --build
# or
docker build -t idp-playground:latest -f docker/Dockerfile .
```

## License

This project is licensed under the **Apache License 2.0** — see the [`LICENSE`](LICENSE) file.
Apache-2.0 includes an explicit patent grant, which is useful for a protocol implementation.

## Trademarks & Affiliation

This is an **independent, educational demo**. It is **not affiliated with, endorsed by, or
sponsored by** Microsoft, HashiCorp, Okta, Google, or any other company.

All product names, logos, and brands are the property of their respective owners.
Microsoft, Azure, Microsoft Entra, Active Directory, AD FS, SharePoint, Dynamics,
Windows, Okta, Google Authenticator, Authy, HashiCorp, and Vault are trademarks or
registered trademarks of their respective owners, referenced here only descriptively to
explain protocol compatibility and comparisons. See the [`NOTICE`](NOTICE) file for details.

This software implements **published open standards**: OAuth 2.0 (RFC 6749) + PKCE (RFC 7636),
OpenID Connect Core 1.0, SAML 2.0 (OASIS), and WS-Federation 1.2 (OASIS). Implementing these
open specifications is expressly permitted.

## Disclaimer — not for production

This is a **learning/demo tool only**. It ships with seeded demo credentials, fixed development
secret keys, a self-signed certificate authority, and debug mode enabled. **Do not use it to
protect real accounts, real data, or any production system.** It is provided "AS IS", without
warranty of any kind, and the authors accept no liability for any use.
