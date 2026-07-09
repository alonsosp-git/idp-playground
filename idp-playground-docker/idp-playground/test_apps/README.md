# IDP-Playground Test Apps

Two test clients for verifying IDP-Playground is working correctly.

---

## Option 1 — Offline Tester (ZERO dependencies)

**File:** `offline_tester/index.html`

Open directly in any browser — no server, no Python, no internet required.

### What it tests:
- Full login wall with credential validation
- MFA challenge (TOTP simulation — enter `123456`)
- JWT generation with realistic RS256 structure
- Token decoder / claims display
- Group membership rendering
- Session persistence (survives page refresh via sessionStorage)
- Live connection tests to your IDP-Playground instance (optional)

### Demo accounts (match IDP-Playground seed data):
| UPN | Password | MFA |
|-----|----------|-----|
| administrator@corp.idp-playground.local | Admin@IDP-Playground1 | ✓ (enter 123456) |
| john.smith@corp.idp-playground.local | Welcome@1 | No |
| maria.jones@corp.idp-playground.local | Welcome@1 | No |
| r.lee@corp.idp-playground.local | Welcome@1 | ✓ (enter 123456) |

### How to open:
```
Double-click offline_tester/index.html
```
or
```
file:///path/to/offline_tester/index.html
```

---

## Option 2 — Flask Live Client (requires IDP-Playground running)

**File:** `oidc_client/app.py`

A real Flask app at `localhost:5000` that connects to IDP-Playground at `localhost:8080`.

### What it tests:
- Auto-registers itself as an OIDC client in IDP-Playground on first run
- Real credential lookup against IDP-DS user directory
- Real JWT issuance via IDP-TS token endpoint
- Full token decode and claims display
- `/api/me` JSON endpoint for integration testing

### Run:
```bash
# Terminal 1 — start IDP-Playground
cd path/to/idp-playground
python app.py          # runs on :8080

# Terminal 2 — start test client
cd test_apps/oidc_client
pip install flask requests
python app.py          # runs on :5000

# Open browser
http://localhost:5000
```

### Flow:
```
User visits localhost:5000
  → Clicks "Sign in with IDP-Playground"
  → Enters credentials on /login page
  → Flask calls IDP-Playground /api/ds/users to find user
  → Flask calls IDP-Playground /api/fs/tokens/issue
  → IDP-Playground returns signed RS256 JWT
  → Flask stores token in session
  → User sees their claims, groups, decoded JWT
```

### Test the JSON API:
```bash
# After logging in via the browser:
curl http://localhost:5000/api/me
```
Returns the full authenticated user object and token claims as JSON.
