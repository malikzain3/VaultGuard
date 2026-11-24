# VaultGuard

A deliberately small password manager: Node.js + Express + EJS + SQLite (`better-sqlite3`), with all cryptography done through Node's built-in `crypto` module (`scrypt` + `ChaCha20-Poly1305`).

**Project root:** `C:\Users\hp\Desktop\valultguard 1`

---

## 1. How it was created, step by step

This section records what was generated at each stage and where each file lives. All paths below are relative to the project root unless stated otherwise.

### Step 1 — Scaffold (root files)

| File | Why it exists |
| --- | --- |
| `package.json` | Declares dependencies and the `start` / `test` scripts. |
| `.gitignore` | Keeps `node_modules/`, `data/` and `.env` out of version control. |
| `server.js` | Entry point: loads `app.js` and listens on port 3000 (or `PORT`). |

Running `npm install` here generated `node_modules/` and `package-lock.json`. No lockfile was handwritten.

### Step 2 — Databases (`db/`, `services/`)

| File | Why it exists |
| --- | --- |
| `db/init.js` | Creates `data/` and `data/vaults/` on first start, opens `data/accounts.db`, and creates the `accounts` table. |
| `services/accounts.js` | Account password hashing/verification (scrypt + `timingSafeEqual`) and account lookups. All queries are parameterised. |
| `services/vault.js` | Opens/creates `data/vaults/<account_id>.db`, creates the `entries` table, and adds/lists/reveals encrypted entries. |

**Runtime-generated data (not committed):**
- `data/accounts.db` — created the first time the app starts.
- `data/vaults/<account_id>.db` — created at sign-up, in the same request that creates the account.

### Step 3 — Crypto service (`services/crypto.js`)

This is the only place that touches cryptography for vault data. It exports:

- `deriveKey(password, salt, options)` — scrypt with `N = 2^15`, `r = 8`, `p = 1` by default (32-byte key, explicit 64 MB `maxmem`).
- `encrypt(key, plaintext, nonce?)` — ChaCha20-Poly1305, 12-byte random nonce, 16-byte Poly1305 auth tag.
- `decrypt(key, ciphertext, nonce, authTag)` — throws `INTEGRITY_FAILED` if the tag does not verify; never returns unverified plaintext.
- `fieldKey(key, label)`, `createMasterVerifier`, `verifyMasterVerifier` — small helpers explained in §5.

### Step 4 — Routes and middleware (`routes/`, `middleware/`, `app.js`)

| File | Responsibility |
| --- | --- |
| `routes/auth.js` | `/`, `/auth`, `/auth/signup`, `/auth/login`, `/logout`. Duplicate-email error, session regeneration on login/signup. |
| `routes/master.js` | `/master/setup` and `/master/unlock` (first-login master creation and later verification). |
| `routes/vault.js` | `/dashboard`, `POST /entries`, `POST /entries/:id/reveal`. |
| `middleware/auth.js` | `requireAuth`, `requireMaster`, and a 15-minute inactivity check that drops the in-memory key. |
| `middleware/csrf.js` | Session-bound double-submit CSRF token, compared with `timingSafeEqual`. |
| `app.js` | Wires helmet, static files, URL-encoded bodies, `express-session`, CSRF, routes and a 404 page. |
| `services/validation.js` | Small input validators for email, passwords and text fields. |

Session cookie: `httpOnly`, `sameSite: 'strict'`, `secure` when `NODE_ENV=production`, 15-minute rolling lifetime. The derived master key is stored **only** as base64 in the server-side session (`req.session.key`) and is deleted on logout or timeout.

### Step 5 — UI (`views/`, `public/`)

| File | Purpose |
| --- | --- |
| `views/partials/header.ejs` / `footer.ejs` | Shared page shell, skip link, viewport meta, stylesheet. |
| `views/auth.ejs` | One page with separate sign-up and sign-in forms. |
| `views/master-setup.ejs` | First-login master password + confirmation. |
| `views/master-unlock.ejs` | Later-login master password verification. |
| `views/dashboard.ejs` | Add-entry form, sorted entry list, Reveal action, reveal panel. |
| `views/error.ejs` | Generic friendly error page (also used for CSRF rejection and 404). |
| `public/styles.css` | The whole design system: CSS variables, responsive grids, focus rings, alert styles, accessible colors. |

The `ui-ux-pro-max` skill was **not available** in this environment (see §8), so its approach was applied by hand: clean minimal layout, consistent 8px-ish spacing, one accent color, fluid typography, mobile-first responsive grids, visible focus states, semantic labels, `role="alert"`/`role="status"` messages, and no JavaScript dependency for any security action.

### Step 6 — Tests (`test/`)

`test/crypto.test.js` uses Node's built-in `node:test` runner (no test framework dependency). It covers round-trip encryption, tampered-tag rejection, wrong-key rejection and scrypt determinism/salt sensitivity.

### Step 7 — Verification

The server was started with `npm start` and the whole flow was exercised over HTTP with a temporary script outside the project (`C:\Users\hp\AppData\Local\Temp\opencode\vaultguard-smoke.js`): sign-up, master setup, add entry, reveal, CSRF rejection, logout, login, wrong master password, correct master password, and an out-of-band auth-tag tamper check. Results are in §9.

---

## 2. Setup and run

Requirements: Node.js 20+ (built and verified on Node 24 LTS), npm.

```powershell
cd "C:\Users\hp\Desktop\valultguard 1"
npm install
npm start
```

Then open **http://localhost:3000**.

Optional environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `PORT` | `3000` | HTTP port. |
| `SESSION_SECRET` | random per process | Set this in production so sessions survive a restart. |
| `NODE_ENV` | unset | Set to `production` to add the `Secure` flag to cookies (requires HTTPS). |

First use:

1. Use the **Create account** form. A duplicate email shows a clear error.
2. Choose a **master password** (minimum 12 characters) and confirm it.
3. Add entries from the dashboard. Only the app name is stored in plaintext.
4. Press **Reveal** on an entry to decrypt and display the credentials for that request. Press **Hide** to clear them from the page.
5. Sign out. Next time, sign in with the account password, then unlock with the master password.

---

## 3. Data flow: scrypt → key → ChaCha20-Poly1305 → vault DB

**Account password (sign-in only).** `services/accounts.js` generates a random 16-byte salt, runs `scrypt(password, salt, 64)` and stores `password_salt` + `password_hash` in `accounts.db`. Login re-derives the hash and compares with `crypto.timingSafeEqual`. The account password never encrypts vault data.

**Master key (vault key).** On first login, `services/crypto.js` derives a 32-byte key with `scrypt(masterPassword, masterSalt, 32, { N: 32768, r: 8, p: 1, maxmem: 64 MB })`. Only the random `master_salt` and an HMAC-SHA256 verification value (`createMasterVerifier`) are saved in `accounts.db`. The master password and the key are never written to disk. On later logins the key is re-derived from the stored salt and checked against the verifier with `timingSafeEqual`; it is then kept in the server-side session only.

**Encryption.** For each entry, `services/vault.js` generates one fresh random 12-byte nonce. ChaCha20-Poly1305 encrypts the username and the password, producing ciphertexts and two 16-byte auth tags. The ciphertexts, the single nonce, and the two tags concatenated into one 32-byte `auth_tag` blob are inserted into `data/vaults/<account_id>.db` with parameterised SQL. `app_name` is stored as plain text so entries can be listed without unlocking any content.

**Decryption / reveal.** `decrypt()` sets the stored auth tag before finalising. If the tag was altered, or a different key is used, Node throws and the service raises `INTEGRITY_FAILED`; the route renders **"Data integrity check failed"** and no plaintext. Verified plaintext is rendered only in the response for that one reveal request.

**Why per-field HMAC subkeys?** The schema stores a single nonce per entry. Using the same key *and* the same nonce for both the username and the password would be nonce reuse under one key. `fieldKey(key, 'username')` and `fieldKey(key, 'password')` derive two independent subkeys from the session key, so the stored nonce is used once per key. The subkeys are recomputed when needed and never stored.

---

## 4. Security notes

- All SQL uses `?` placeholders; no string-built queries.
- CSRF token required on every POST, compared in constant time; session cookie is `httpOnly` + `sameSite=strict` (+ `Secure` in production).
- `helmet` sets security headers, including a content-security policy compatible with the external stylesheet.
- Session IDs are regenerated at sign-up/login; the session key is removed on logout and after 15 minutes of inactivity.
- Inputs are validated and length-limited; EJS auto-escapes rendered values; no secrets are logged.
- Only built-in `crypto` primitives are used — no third-party crypto library.

---

## 5. Tests

```powershell
cd "C:\Users\hp\Desktop\valultguard 1"
npm test
```

Four tests run via `node --test`: round-trip, tampered-tag rejection, wrong-key rejection, and `deriveKey` determinism/salt sensitivity.

---

## 6. Skills and tooling notes

- **`ui-ux-pro-max`:** requested for the design, but it is not part of the installed skill set in this environment. Nothing was installed for it; the approach (clean, minimal, accessible, responsive, clear states/messages) was applied manually in `public/styles.css` and the EJS views.
- **Other skills:** the **Browser** skill was loaded and used for a final structural/visual check of `/auth` (accessibility snapshot + console errors). A screenshot was captured, but this model cannot display images, so the accessibility tree and zero console errors were used as the visual check.
- **No other skills were installed.** Dependencies came from npm: `express`, `ejs`, `better-sqlite3`, `express-session`, `helmet`. Tests use Node's built-in `node:test`; CSRF uses Node's built-in `crypto`.
- `git` is not installed on this machine, so no repository was initialised.

---

## 7. Verification results

All checks passed on a running server:

1. `GET /auth` renders both forms, no console errors.
2. Sign-up creates the account and vault DB and redirects to master setup.
3. Master setup saves only salt + verifier and places the key in the session.
4. Adding an entry stores ciphertext, nonce and tag; the list page contains no plaintext.
5. POST without a CSRF token is rejected with HTTP 403.
6. Reveal decrypts and shows the correct username and password.
7. Logout destroys the session; `/dashboard` redirects to `/auth`.
8. Login with the account password goes to master unlock.
9. A wrong master password shows "Master password verification failed".
10. The correct master password unlocks the vault and reveal works again.
11. Flipping a byte of the stored auth tag produces exactly "Data integrity check failed" and no plaintext.

---

## 8. Deliberate limitations

This is a minimal demo, not a production deployment:

- `express-session` uses its default in-memory store; use a persistent store for real deployments.
- There is no account recovery — losing the master password means losing vault access.
- CSRF protection is a compact session-bound token implementation rather than a separate package.
- Only one vault per account, and no entry edit/delete flows (as specified).
