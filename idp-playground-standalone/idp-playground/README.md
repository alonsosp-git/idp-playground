# IDP-Playground Identity Platform — running without Docker

This is the plain, run-it-directly version of IDP-Playground: the identity server
plus the four protocol test clients (OIDC, SAML, OAuth2, WS-Federation). You run
each piece with `python`, no containers involved.

## What each piece is for

IDP-Playground is a self-contained identity platform you can run on your own machine.
It plays the role a company's central login system plays: it stores user
accounts and it issues the security tokens that let those users sign in to other
applications. It has two internal modules, plus four small demo applications that
show it working with the major single-sign-on standards.

### The IDP-Playground server (port 8080) — the identity provider

This is the admin console and the engine. It has two parts:

- **IDP-DS — Directory Domain Services.** The directory. This is where user
  accounts, groups, domains, and organizational units live — the master list of
  "who exists," each person's attributes (name, email, department), and their
  group memberships. In this demo it also stores each user's multi-factor
  authentication settings and any client certificates issued to them.

- **IDP-TS — Token Generator Service.** The token engine. When a user logs in,
  this module produces the signed proof of identity (a token) that an
  application will trust. It speaks the common single-sign-on standards — OIDC,
  SAML 2.0, OAuth 2.0, and WS-Federation — so different kinds of applications can
  all authenticate against the same directory. It also holds the list of
  registered applications and the signing certificate used to prove the tokens
  are genuine.

Together: IDP-DS knows *who the user is*; IDP-TS *vouches for them* to an
application in whatever token format that application understands.

### The four test applications (ports 5000–5003)

These are small stand-in "business applications" — the kind of app an employee
would log into. Each is built around a different single-sign-on standard so you
can see IDP-Playground serve all of them. None store passwords; they delegate login to
IDP-Playground and receive a token back. Each one shows you the token it received,
decodes it, and (with the built-in traffic capture) lets you watch the requests.

- **OIDC test client (port 5000)** — **OpenID Connect**, the modern login
  standard behind many "Sign in with…" buttons. Best first app to try.
- **SAML test client (port 5001)** — **SAML 2.0**, the established enterprise
  standard used by many corporate and SaaS apps. Shows the signed "assertion."
- **OAuth2 test client (port 5002)** — **OAuth 2.0 with PKCE**, the
  authorization-code flow used by single-page and mobile apps.
- **WS-Fed test client (port 5003)** — **WS-Federation**, an older standard
  common in Microsoft-oriented enterprises.

If you just want to see a login work, start with OIDC. For enterprise SSO, SAML
is the most representative — the tutorial below uses it.

## Requirements

- Python 3.10 or newer (3.12 recommended)
- The Python packages in `requirements.txt`

## Install

From the project folder:

```bash
pip install -r requirements.txt
```

The test clients also use `requests` (not in the base requirements):

```bash
pip install requests
```

On some systems use `pip3`. To keep things isolated you can use a virtual
environment:

```bash
python -m venv .venv
# Windows:      .venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt requests
```

## Run

Start the **server first**, then each client you want, each in its own terminal.

1. Start the identity server:

   ```bash
   python idp_playground_server.py
   ```

   Listens on http://localhost:8080 and seeds its database on first run.

2. In separate terminals, start whichever test clients you want:

   ```bash
   python test_apps/oidc_client/testclient_oidc.py     # http://localhost:5000
   python test_apps/saml_client/testclient_saml.py     # http://localhost:5001
   python test_apps/oauth2_client/testclient_oauth2.py # http://localhost:5002
   python test_apps/wsfed_client/testclient_wsfed.py   # http://localhost:5003
   ```

3. Open the admin console at **http://localhost:8080** and the clients on
   5000–5003.

To confirm a client is the current build, open its `/version` URL, e.g.
http://localhost:5000/version.

| Service            | Port | URL                     |
|--------------------|------|-------------------------|
| IDP-Playground admin/IdP| 8080 | http://localhost:8080   |
| OIDC test client   | 5000 | http://localhost:5000   |
| SAML test client   | 5001 | http://localhost:5001   |
| OAuth2 test client | 5002 | http://localhost:5002   |
| WS-Fed test client | 5003 | http://localhost:5003   |

Default admin login: `administrator@corp.idp-playground.local` / `Admin@IDP-Playground1`

Stop a service with Ctrl+C in its terminal. The database is a local SQLite file
under `instance/`; delete it to reset everything to a fresh seed.

### The traffic capture panel

Every test app has a small **TRAFFIC CAPTURE** panel (Start / Stop / Download /
View / Clear) in the corner. Turn it on before you log in and it records every
request the app makes, including the calls to IDP-Playground, so you can watch and
download the actual login traffic.

## Tutorial: log in "John Smith" to the SAML app, every which way

A complete, click-by-click walkthrough using the pre-created demo user
**John Smith** and the **SAML test app**. It shows how to set up and then log in
with each authentication method: password only, authenticator code, email code,
certificate, and passkey PIN. The demo user and the SAML app already exist — you
don't need to create anything.

Make sure the **server (8080)** and the **SAML client (5001)** are both running.

Two pages are involved:
- The **admin console** at http://localhost:8080 — where you configure the user.
- The **SAML app** at http://localhost:5001 — where "John Smith" logs in.

The demo accounts:

| Account       | Sign-in name                          | Password           |
|---------------|---------------------------------------|--------------------|
| Administrator | `administrator@corp.idp-playground.local`  | `Admin@IDP-Playground1` |
| John Smith    | `john.smith@corp.idp-playground.local`     | `Welcome@1`        |

### Part 0 — First, a plain login (password only)

1. Open the SAML app at **http://localhost:5001**.
2. Click **Initiate SAML SSO**. The app hands you off to IDP-Playground to log in.
3. Enter John Smith's sign-in name `john.smith@corp.idp-playground.local` and password
   `Welcome@1`, and continue.
4. You're sent back to the SAML app, signed in, and you'll see the **SAML
   assertion** (the signed statement of who you are) and John Smith's details.

That's a basic single-sign-on login with no second factor. Everything below adds
multi-factor (MFA) on top of it.

> Tip: click **Start** on the TRAFFIC CAPTURE panel before step 2 to record the
> exchange, then **View** or **Download** it afterward.

### Part 1 — Turn on multi-factor for John Smith (admin side)

Do this in the **admin console**. You only need the sub-section for the method
you want to try; you can set up several and pick one at login.

1. Open **http://localhost:8080** and sign in as the administrator
   (`administrator@corp.idp-playground.local` / `Admin@IDP-Playground1`).
2. Go to **IDP-DS → Users**.
3. Find **John Smith**, and in his row click **Enable MFA** (or **Configure MFA**
   if it's already on) to open the setup dialog. A legend shows which methods are
   already configured.

Then set up whichever method(s) you want:

#### Method A — Authenticator app (6-digit code)

1. Choose **Authenticator App**.
2. Scan the QR code with any authenticator app (Google Authenticator, Microsoft
   Authenticator, Authy, etc.). It starts showing a 6-digit code that rotates
   every 30 seconds.
3. Type the current code into the dialog to confirm, and save.

#### Method B — Email one-time code

1. Choose **Email OTP**.
2. Confirm the user's email and save. At login, IDP-Playground generates a one-time
   code for that address. (Email may be simulated in this demo; the code is shown
   to you so you can finish the login without a real mail server. Configure SMTP
   in the server settings for real email.)

#### Method C — Certificate (a client certificate file)

1. Choose **Certificate (CBA)**.
2. Click **Generate Certificate for this user**. IDP-Playground creates and downloads
   a certificate. Wait for the download to finish and note where it saved (a real
   file of roughly 1–4 KB; a `.cer`/`.pem` or `.p12` both work). If you ever get a
   tiny file, generate again.
3. Keep that file handy for login.

#### Method D — Passkey PIN (a 4-digit PIN)

1. Choose **Passkey (WebAuthn)**.
2. In the passkey section, set a **4-digit PIN** (e.g. `1234`) and save. (A
   hardware key / Windows Hello option also exists, but the PIN is the easy path
   and needs no special hardware.)

When done, the dialog's legend should show a green "MFA is active" line listing
your methods. Close the dialog.

### Part 2 — Log in to the SAML app with the second factor

1. Open the SAML app at **http://localhost:5001** (use a private/incognito window
   if you're still signed in as admin elsewhere, so the sessions don't mix).
2. Click **Initiate SAML SSO**.
3. Enter John Smith's sign-in name and password (`Welcome@1`).
4. IDP-Playground now shows a **Verify Your Identity** screen with tabs: **Code**,
   **Certificate**, and **Passkey**. Use the one matching what you set up:

   - **Authenticator app (A):** on the **Code** tab, enter the current 6-digit
     code from your authenticator app and submit.
   - **Email code (B):** on the **Code** tab, enter the one-time code sent to the
     email (shown on screen in the demo) and submit.
   - **Certificate (C):** on the **Certificate** tab, drag the downloaded
     certificate file into the drop area (or click to browse), then click
     **Verify Certificate & Sign In**.
   - **Passkey PIN (D):** on the **Passkey** tab, type your 4-digit PIN (e.g.
     `1234`) and submit.

5. On success you return to the SAML app, signed in, and can explore John Smith's
   assertion and attributes with the navigation tabs.

The same pattern works for OIDC (5000), OAuth2 (5002), and WS-Fed (5003) — only
the app you start from changes; the IDP-Playground login and MFA screens are the same.

### If something doesn't work

- **"Not recognized" on a certificate:** re-download it from the user's MFA
  dialog (a few KB, not tiny) and upload that fresh copy.
- **Code rejected:** authenticator codes are time-based — check your device clock
  and enter the current code before it rotates.
- **You see the admin instead of John Smith:** you're still logged in as admin in
  that browser; use a separate/incognito window for John Smith.
- **The MFA tab you want isn't shown:** that method isn't configured for the user
  yet. Go back to Part 1 and set it up.
- **A client shows "IDP-Playground not reachable":** make sure `idp_playground_server.py`
  is running on port 8080, and start it before the clients.

## Notes

- This is a demo/development build: it uses Flask's built-in server and a local
  SQLite database, which are fine for evaluation but not production load.
- Default seeded credentials are public (see the table above). Change the admin
  password before exposing this anywhere beyond your own machine.
- The database lives in `instance/idp_playground.db` and is created automatically.
  Delete the `instance/` folder to start over from a clean seed.

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
