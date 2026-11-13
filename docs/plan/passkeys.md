# Passkeys (WebAuthn) for OxiCloud login

**Status**: Phase 1 IMPLEMENTED (2026-11-12, branch `feat/passkeys`), with the
deviations listed under "Phase 1 as built". Phase 2a IN PROGRESS (branch
`feat/passkeys-phase2`, see "Phase 2a plan"); 2b and 3 planned.

**Related**: `docs/architecture/auth-model.md` (lists native WebAuthn as a
future feature and reserves the `mfa_enrolled` magic-link rejection),
`docs/plan/auth-simplification.md`, `docs/plan/dpop.md` (session binding;
passkeys are orthogonal), `docs/plan/chat-matrix.md` (OxiCloud is the
identity provider for Matrix, so a passkey login protects chat too).

## Why

OxiCloud has no multi-factor login of its own: MFA exists only for accounts
that sign in through an external OIDC provider. A self-hoster running
OxiCloud without one (the common case, and the `mx` deployment) has
password-only accounts, and since OxiCloud is also the IdP for Matrix
(`idp_handler.rs`), one leaked password opens files, calendar and chat.

Passkeys fix both halves of the usual problem: they cannot be phished
(the browser binds them to the site), and they need no second app.

## Goals

1. **Passwordless sign-in with a passkey** (Phase 1). A user registers one
   or more passkeys in their profile and can then sign in with one instead
   of the password.
2. **Passkey as second factor** (Phase 2). A user, or an admin policy, can
   require a passkey after the password. Every way into a session honours
   it.
3. **Chat recovery key unlocked by passkey** (Phase 3). The WebAuthn PRF
   extension gives the browser a secret only the passkey can produce;
   OxiCloud stores the Matrix recovery key encrypted with it and never sees
   it in plaintext.

## Non-goals

- TOTP. Passkeys cover the same threat better; TOTP can follow under the
  same policy later.
- Passkeys for WebDAV, CalDAV, CardDAV and Nextcloud sync clients. These
  use app passwords and stay that way; see "Entry points".
- Attestation (proving which authenticator model made the key).
  `attestation: "none"`; enterprise attestation policy is a later concern.
- Replacing external OIDC. A deployment with an IdP keeps using it; for
  OIDC-linked accounts the IdP stays the security boundary.

## Decisions

### Library

- **Server**: `webauthn-rs` 0.6 (MPL-2.0, which an MIT project may depend
  on; RustCrypto since 0.6, so no OpenSSL). Registration with
  `start_passkey_registration` / `finish_passkey_registration`; username-less
  sign-in with `start_discoverable_authentication` /
  `identify_discoverable_authentication` /
  `finish_discoverable_authentication`, which need the crate's
  `conditional-ui` feature (stored `Passkey`s convert to `DiscoverableKey`).
  Ceremony state stays in memory, so `danger-allow-state-serialisation` is
  not needed. Check the full dependency tree's licences before merging, per
  AGENTS.md.
- The crate's own guidance: synced passkeys (iCloud Keychain, Google
  Password Manager) can be copied, so it recommends them only alongside a
  second factor. Phase 1 accepts that for passwordless sign-in, the same
  trade every passkey-only site makes; Phase 2's policy lets an operator
  require password + passkey instead.
- **Browser**: no npm package. `navigator.credentials.create()` / `.get()`
  plus base64url conversion, a few dozen lines in
  `frontend/src/lib/auth/passkey.ts`.

### Relying party

- **RP ID** = host of the configured public URL (`AppConfig::base_url()`,
  i.e. `OXICLOUD_BASE_URL`). **RP origin** = that URL's origin.
- Passkeys are bound to the RP ID: changing the deployment's domain later
  makes every registered passkey useless. Document this in
  `docs/config/authentication.md` and log a startup warning when
  `OXICLOUD_BASE_URL` is unset and the RP ID falls back to
  `server_host` (a dev default that must not reach production).
- Feature flag: `OXICLOUD_PASSKEYS_ENABLED`, default **on** once Phase 1
  ships, since it only adds an option.

### Data model

New migration, `auth` schema:

```sql
CREATE TABLE auth.passkeys (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,     -- lookup on sign-in
    passkey       JSONB NOT NULL,            -- serialized webauthn_rs::Passkey
    name          TEXT NOT NULL,             -- "MacBook", user-editable
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ,
    -- Phase 3: PRF-wrapped secrets live in their own table, keyed by this id.
    CONSTRAINT passkeys_name_len CHECK (char_length(name) BETWEEN 1 AND 64)
);
CREATE INDEX passkeys_user_id ON auth.passkeys(user_id);
```

- The `Passkey` JSON carries the public key and signature counter;
  `finish_passkey_authentication` returns an updated credential that must
  be written back (counter and backup state). A failed write-back fails the
  login rather than silently dropping the counter update.
- **Ceremony state** (`PasskeyRegistration`, `PasskeyAuthentication`)
  lives server-side for at most 5 minutes, keyed by a random id returned to
  the browser. Short-lived and single-use, so a moka cache in the service
  is enough at the 10k-user target; it does not survive a restart, which
  only means a ceremony in flight has to be restarted.
- `SessionOrigin::Passkey` (`"passkey"`), added next to `Opaque`,
  `MagicLink`, `Oidc`. The sessions-list UI shows it, and the DB CHECK
  constraint on the origin column gains the value.

### Service and routes

`PasskeyService` in `application/services/`, built in `common/di.rs` as
`Option<Arc<_>>` like the other optional auth services. Ownership checks in
the service (`caller_id` on every method), never in handlers.

| Route | Auth | Does |
|---|---|---|
| `POST /api/auth/passkeys/register/start` | session | returns `CreationChallengeResponse` + ceremony id; excludes the user's existing credentials |
| `POST /api/auth/passkeys/register/finish` | session | verifies, stores with a name |
| `GET /api/auth/passkeys` | session | the caller's passkeys (name, created, last used) |
| `PATCH /api/auth/passkeys/{id}` | session | rename |
| `DELETE /api/auth/passkeys/{id}` | session + recent auth | remove (see "Lockout") |
| `POST /api/auth/passkey/login/start` | public | discoverable-credential challenge (no username needed) |
| `POST /api/auth/passkey/login/finish` | public | verifies, then `mint_session_for_authenticated_user(…, SessionOrigin::Passkey)` |

- Sign-in uses **discoverable credentials**: the browser offers the
  account, so the login page shows "Sign in with a passkey" without asking
  for a username first. That also allows conditional UI
  (`mediation: "conditional"`, passkeys in the username field's autofill).
  `identify_discoverable_authentication` yields the credential's user
  handle; the service maps it to the user and loads their keys.
- Registration asks for a discoverable credential
  (`residentKey: "preferred"`). webauthn-rs discourages residency to spare
  the limited slots on hardware keys; a hardware key that declines still
  works through Phase 2's username-first path, and every platform passkey
  manager creates discoverable keys anyway.
- Login finish reuses `mint_session_for_authenticated_user`, so DPoP
  binding, lifecycle hooks, `last_login_at` and session rows behave exactly
  as for OPAQUE. Rate limiting reuses the login limiters.
- **Registration requires a recent authentication**: a session older than
  N minutes must re-enter the password (or use an existing passkey) before
  adding a passkey, so a stolen session cookie cannot plant one.
- Deactivated accounts and pending password changes are rejected the same
  way the password path rejects them (`lookup_user_for_login` rules).

### Audit

Per AGENTS.md, every rejection logs on `target: "audit"` before returning:

- `passkey.login_rejected`, reasons `unknown_credential`,
  `verification_failed`, `account_deactivated`, `ceremony_expired`,
  `counter_regressed`.
- `passkey.registration_rejected`, reasons `reauth_required`,
  `verification_failed`, `ceremony_expired`, `duplicate_credential`.
- Success is `info` for registration and removal (security-relevant
  changes to the account), `debug` for each sign-in.

## Entry points

A second factor is only as strong as the weakest way in. Phase 1 adds a
door; Phase 2 must make every door check the policy.

| Entry point | Phase 1 (passwordless) | Phase 2 (passkey required) |
|---|---|---|
| OPAQUE password login (`opaque_auth_handler.rs`) | unchanged | password success returns `mfa_required` + ceremony instead of a session |
| Legacy password login (`login`) | unchanged | same as OPAQUE |
| Magic link (`magic_link_eligibility`) | unchanged | new `Reject("mfa_enrolled")` branch, as auth-model.md reserves |
| OIDC | unchanged | unchanged: the IdP owns MFA for OIDC users |
| Nextcloud login flow v2 (`login_v2_handler.rs`) | **gap**: it calls `verify_credentials(username, password)`, so a user without a password cannot link a desktop client. Add "grant with my current session" when the browser is signed in | the password form path must also complete the passkey step |
| Device flow (`SessionOrigin::Device`) | unchanged (approval happens in a signed-in browser) | approval requires a session that passed the policy |
| App passwords (WebDAV, DAV, NC sync) | unchanged | unchanged, deliberately. Creating one requires a session that passed the policy, so the factor is checked at issue time |
| OxiCloud as IdP (`idp_handler.rs`, Matrix and others) | works: `authorize` uses the browser session | inherits whatever the session passed |
| Admin password reset / setup | unchanged | an admin reset of a passkey-required user keeps the requirement |

## Lockout and recovery

- Removing the **last** passkey of a user who has no password (or who is
  under a passkey-required policy) is refused unless a recovery path
  exists: `passkey.removal_rejected`, reason `last_factor`.
- Phase 1 keeps the password as the fallback; users who want to drop the
  password entirely can, once they have two passkeys.
- Phase 2 adds **recovery codes**: 10 single-use codes, shown once, stored
  hashed (Argon2, as passwords). Generating new codes revokes the old set.
- Admins can always remove a user's passkeys from the admin user page,
  which logs `passkey.admin_reset`.

## Frontend

- **Login page**: a "Sign in with a passkey" button, and conditional UI on
  the username field where the browser supports it. Shown only when
  `/api/config` reports `features.passkeys`.
- **Profile → Security**: list with name, created, last used; add, rename,
  remove. Uses `formDialog` / `confirmDialog`.
- **Phase 2**: the second step after the password, a policy toggle in the
  user's security settings, and an admin policy (off / optional / required
  for admins / required for everyone).
- Strings in all 16 locales; `scripts/check-locales.mjs` must pass.

## Phase 3: chat recovery key behind a passkey

- At passkey sign-in, request the PRF extension
  (`extensions: { prf: { eval: { first: <per-user salt> } } }`). The
  browser returns 32 bytes only that passkey can produce for that salt.
- The chat page derives an AES-GCM key from it (HKDF, `info =
  "oxicloud-chat-recovery-key"`) and stores the encrypted Matrix recovery
  key at `PUT /api/auth/passkeys/{id}/secrets/chat-recovery-key`. OxiCloud
  stores ciphertext and salt only.
- On a new browser, after a passkey sign-in, the chat page fetches the
  blob, decrypts it with the PRF output and unlocks without asking.
- PRF support varies by authenticator and browser; when it is missing, the
  chat page keeps asking for the key as today. Each passkey gets its own
  wrapped copy, created the first time the user unlocks chat with it.
- This matches the privacy axis in AGENTS.md: the server never holds a
  readable copy, so end-to-end encryption still holds against the server.

## Tests

- **Rust unit tests**: ceremony expiry, counter write-back, last-factor
  refusal, `magic_link_eligibility` with `mfa_enrolled` (Phase 2),
  RP ID derivation from `base_url()`.
- **Hurl** (`tests/api/passkeys.hurl`): status codes and shapes of every
  route, unauthenticated access to session routes refused, one user cannot
  list, rename or delete another user's passkey (404, not 403), expired
  ceremony id rejected. The ceremonies themselves need an authenticator, so
  Hurl covers the refusals and shapes, not a full sign-in.
- **Full ceremony**: a Rust integration test drives `webauthn-rs`'s
  software authenticator (`webauthn-authenticator-rs`, dev-dependency only)
  through register + login + counter update.
- **Vitest**: base64url conversion and the credential (de)serialisation in
  `passkey.ts`.
- **Playwright** (optional): Chromium's virtual authenticator via CDP for
  one end-to-end sign-in.

## Phases

1. **Passwordless sign-in**: migration, `PasskeyService`, the seven routes,
   `SessionOrigin::Passkey`, login button and profile management, login
   flow v2 "grant with current session", audit lines, tests. Done when a
   user can register a passkey, sign in with it in another browser, and
   reach Matrix chat through the IdP in that session.
2. **Second factor**: user and admin policy, the step after the password,
   magic-link `mfa_enrolled`, recovery codes, every row of the entry-point
   table enforced and pinned in Hurl.
3. **Chat recovery key via PRF**: secrets table and routes, chat page
   integration.

## Phase 1 as built

Where the build differs from the design above, and why:

- **Flag name** `OXICLOUD_ENABLE_PASSKEYS` (not `OXICLOUD_PASSKEYS_ENABLED`),
  matching every other `OXICLOUD_ENABLE_*` feature flag.
- **No recent-authentication check before registering.** `CurrentUser`
  carries no login time (only the JWT's `sid`), so "session younger than N
  minutes" needs new plumbing. Phase 1 relies on what already protects the
  session (HttpOnly cookies, CSRF, DPoP binding) and audits every
  registration (`passkey.registered`). Moved to Phase 2, where the same
  step-up is needed anyway.
- **Nextcloud login flow v2 "grant with my current session"** is not built
  yet. Phase 1 keeps passwords, so nobody is locked out of linking a
  desktop client; it becomes necessary before anyone may drop their
  password, i.e. with Phase 2.
- **Narrow user port.** `UserStoragePort` is not object-safe, so the
  service reads users through `PasskeyUserPort` (as the IdP does). Its
  `has_other_login` counts a password hash, an OPAQUE envelope or a linked
  OIDC identity; magic links don't count.
- **Externals cannot register passkeys** (`passkey.registration_rejected`,
  reason `external_user`): they sign in by magic link and own nothing.
- **Routes**: `/api/auth/passkeys` (signed in: `GET /`, `POST
  /register/start`, `POST /register/finish`, `PATCH /{id}`, `DELETE /{id}`)
  and `/api/auth/passkey/login` (public: `POST /start`, `POST /finish`,
  behind the login rate limiter). The public prefix is in the SPA's
  `AUTH_PRIMITIVES`, the signed-in one is not.
- **Login cookies** now come from one helper,
  `cookie_auth::append_login_cookies`, used by every login path (password,
  OPAQUE, magic link, refresh, passkey).
- **Tests**: Rust ceremonies against `webauthn-authenticator-rs`'s
  `SoftPasskey` (dev-dependency) including counter write-back, replay,
  cross-user handles, deactivated accounts, last-factor refusal and the
  option JSON shape; Vitest for the browser conversions;
  `tests/api/passkeys.hurl` for discovery, shapes and refusals. The Hurl
  suite sets `OXICLOUD_BASE_URL` to its `localhost` URL because WebAuthn
  refuses IP hosts.

## Phase 2 split

Phase 2 is two independent parts, built in this order (decided 2026-11-13):

- **2a, living without a password**: step-up re-authentication, Nextcloud
  login flow v2 "grant with my current session", recovery codes, removing
  the password. After 2a a user can run an account on passkeys alone.
- **2b, passkey as second factor**: per-user and admin policy (per role:
  off / optional / required for admins / required for everyone), the step
  after the password, magic-link `mfa_enrolled`, every entry-point row
  enforced, admin passkey reset. Reuses 2a's step-up.

## Phase 2a plan

1. **Step-up ("confirm it's you").** `auth.sessions.authenticated_at`
   records when the user last proved who they are: set when a session is
   minted, carried over on refresh rotation (unlike `created_at`), moved
   forward by a re-authentication. `NULL` on rows that predate the column
   counts as stale.
   - `POST /api/auth/reauth/password` (`{password}`, checked against the
     Argon2 hash like `change_password`) and `POST
     /api/auth/reauth/passkey/{start,finish}` (a passkey of the caller's own
     account). Both stamp the caller's session; refusals audit
     `auth.reauth_rejected`.
   - Window: 10 minutes. Sensitive routes answer 403 `ReauthRequired`
     when the stamp is older; the SPA catches that, shows a "Confirm it's
     you" dialog (passkey, or password when the account has one) and
     retries the request once.
   - Gated in 2a: register a passkey, remove a passkey, generate recovery
     codes, remove the password.
2. **Login flow v2 with the current session.** The `/nextcloud/login`
   page, when the browser is signed in, offers "Continue as <name>". It
   calls `POST /api/nextcloud/login-flow/{token}/grant` (session, CSRF),
   which completes the flow through the same `resolve_drive_or_complete`
   as the password and OIDC paths (label `Nextcloud (session)`). With two
   or more drives the response lists them and the page posts the choice to
   the existing `/login/v2/flow/{token}/drive`. The button is a click,
   never automatic: the flow token comes from whoever started the flow.
3. **Recovery codes.** 10 codes of 16 random base32 characters (80 bits),
   shown once. Stored as SHA-256, not Argon2: the codes are
   high-entropy, so a slow hash adds no protection and would make every
   attempt cost ten Argon2 runs. Generating a new set deletes the old one.
   `POST /api/auth/recovery/login` (`{username, code}`, login rate
   limiter) burns the code and mints a session with origin `recovery`
   that is freshly authenticated, so the user can add a passkey at once.
   Profile shows how many codes are left.
4. **Remove the password.** `DELETE /api/auth/password` (step-up) clears
   `password_hash` and the OPAQUE envelope when the user keeps at least
   two passkeys, or one passkey plus unused recovery codes. OIDC-linked
   accounts are refused (the IdP owns their login). An admin password
   reset gives the password back.

## Open questions

- Should Phase 1 already let a user drop their password entirely, or wait
  for recovery codes in Phase 2? (Proposed: wait.)
- Admin policy granularity: per role only, or per user group as well?
- Does the legacy (non-OPAQUE) password login still need a Phase 2 path, or
  is it retired by then (`docs/plan/opaque-only.md`)?
