# Plan — Chat and calls via Matrix

**Status:** design captured 2026-11-11, **not started**. Supersedes the
"Chat / DM / voice / video" non-goal in [`message-bus.md`](./message-bus.md).

## Context

The feature ambition is Google Workspace / Office 365, and collaboration is
the main feature axis (`AGENTS.md`). Chat and calls are part of that surface.
Two routes were considered and rejected before this plan:

- **Nextcloud Talk compatibility.** The official Talk mobile apps only receive
  background pushes through `push-notifications.nextcloud.com`. That relay
  exists because only the app publisher may hold the APNs/FCM signing
  credentials. An OxiCloud-published fork of the GPLv3 Talk apps would make
  us the keyholder, which means a central relay that every instance depends
  on. On iOS it would also carry the GPL-vs-App-Store distribution risk. With
  our own apps the Talk wire protocol gives us nothing, and it has no
  federation and no E2EE.
- **A home-grown protocol on the message bus.** This means writing every
  client, running a push relay and inventing federation and E2EE. It costs
  the most and gets us the least.

**Decision: Matrix.** It fits every design axis without us owning clients or
push infrastructure:

| Axis | What Matrix gives |
|---|---|
| Decentralised by intent | Server-to-server federation is in the core spec. Each OxiCloud instance is a homeserver. |
| Privacy → E2EE target | Olm/Megolm E2EE, on by default for DMs and private rooms in mainstream clients. |
| Mobile without being the keyholder | The **client** registers a pusher whose gateway URL is chosen by the app publisher (e.g. Element runs one for Element X). The homeserver just POSTs to it. No APNs/FCM credentials touch OxiCloud. |
| Calls | MatrixRTC with a LiveKit SFU, used by Element Call and Element X. Group calls don't need a signaling server of our own. |
| Existing clients | Element X (iOS/Android), Element Web, FluffyChat and others. We ship no mobile app. |

**Cost accepted:** users migrating from Nextcloud lose their Talk app. They
keep the Nextcloud Files app against OxiCloud.

## Goals

1. Every internal OxiCloud user has a Matrix account with the **same login**:
   no second password, no second account to provision or deactivate.
2. Element X works end to end on a stock install: login, DMs, rooms, E2EE,
   background push, 1:1 and group calls.
3. File sharing into chat goes through OxiCloud grants, not by copying bytes
   into the chat media store.
4. Chat activity reaches OxiCloud's notification bell and the SPA.
5. Federation with the wider Matrix network is **an operator choice**, off by
   default.

## Non-goals

- **Writing a homeserver.** The Matrix C-S and S-S specs are years of work,
  and good Apache-2.0 Rust homeservers exist. We integrate one.
- **Writing a mobile app.** Push delivery depends on not being an app
  publisher.
- **Bridges** (Slack, WhatsApp, …). Operators can add appservices themselves.
- **Server-side search or moderation of E2EE content.** The server can't read
  it. That's the point.

## Architecture

```
                         ┌────────────────────────── one deployment ──────────────────────────┐
 Element X / Web ──C-S──▶│  reverse proxy                                                      │
                         │   ├─ /_matrix/*, /_tuwunel/* ──▶ homeserver (sidecar, RocksDB)      │
                         │   ├─ /.well-known/matrix/*  ──▶ OxiCloud (generated)                │
                         │   ├─ /oidc/* , /api/* , SPA ──▶ OxiCloud  ◀── OIDC upstream IdP ──┐ │
                         │   └─ /livekit/*            ──▶ LiveKit SFU                         │ │
                         │                                                                    │ │
                         │  homeserver ──appservice txns──▶ OxiCloud (/_matrix/app/v1/*) ─────┘ │
                         │  homeserver ◀──admin API─────── OxiCloud (provisioning, deactivate)  │
                         │  OxiCloud  ──MatrixRTC token──▶ LiveKit (JWT signed by OxiCloud)     │
                         └───────────────────────────────┬────────────────────────────────────┘
                                                         │ S-S federation (optional)
                                                         ▼
                                              other homeservers / OxiCloud instances

 homeserver ──push (HTTPS)──▶ client-chosen push gateway (e.g. Element's Sygnal) ──▶ APNs / FCM
```

Responsibilities:

- **Homeserver (sidecar):** the whole Matrix C-S and S-S API, the room DAG,
  E2EE key distribution, the media repo, pushers, MatrixRTC transport
  advertisement (MSC4143).
- **OxiCloud:** identity, the user lifecycle, file grants, notifications,
  LiveKit token issuance and the generated well-known documents.
- **LiveKit:** media only.

## Component choice

### Homeserver

Hard criteria, in priority order:

1. **Licence** Apache-2.0 or MIT. Synapse and Element's Matrix Authentication
   Service are AGPL-3.0. They're usable as separate processes, but excluded as
   the bundled default so the stack an operator gets from us stays permissive.
2. **Element X compatible:** Simplified Sliding Sync (MSC4186) and native
   OAuth/OIDC login (MSC3861 family, now in the spec as "OAuth 2.0 API").
3. **Upstream IdP:** the homeserver can delegate identity to an external OIDC
   provider (OxiCloud) while still acting as the OAuth server for clients.
4. **MatrixRTC:** advertises LiveKit foci (MSC4143).
5. **Appservice API**, for the integration seams below.
6. Runs comfortably at 10k users on one node.

| | **Tuwunel** | **Continuwuity** | Synapse + MAS |
|---|---|---|---|
| Licence | Apache-2.0 | Apache-2.0 | AGPL-3.0 (both) |
| Language / storage | Rust / RocksDB | Rust / RocksDB | Python / PostgreSQL |
| Native OAuth server for Element X | yes (1.6.0+, `oidc_native_auth`; requires `well_known.client`) | delegated auth merged 2026-07 (#1886); disables legacy login once enabled | yes (MAS) |
| Upstream OIDC IdP | yes (1.5.0+) | yes | yes |
| MatrixRTC foci config | yes | yes (`[global.matrix_rtc]`) | yes |
| Backing | sponsored by the Swiss government, deployed for citizens | community | Element |

**Recommendation: Tuwunel**, with Continuwuity as the fallback. They share
the conduwuit lineage, so the integration surface (admin API, config style)
is close. Phase 0 makes the final call on a test bench, not on release notes.

Known Tuwunel rough edges to re-check in phase 0: issue #639 (Element X
"Manage account" bypassing the native OIDC page, fixed 2026-10) and issue
#433 (UIA for SSO accounts redirecting to the IdP homepage).

### Calls

- **LiveKit server** (Apache-2.0) as the SFU, run as a sidecar.
- **`lk-jwt-service` is AGPL-3.0**, so we don't bundle it. Its job is small:
  exchange a Matrix OpenID token for a LiveKit JWT. **OxiCloud implements it**
  as an MIT endpoint (see seam 5).
- **TURN:** LiveKit has an embedded TURN server. Use it rather than adding
  coturn.

## Integration seams

### 1. Identity: OxiCloud becomes an OIDC provider

Today OxiCloud is an OIDC **client** only (`infrastructure/services/oidc_service.rs`).
The homeserver needs an upstream IdP, so OxiCloud gains a minimal OpenID
Provider surface:

- `/.well-known/openid-configuration`, `/oidc/authorize` (auth-code + PKCE),
  `/oidc/token`, `/oidc/jwks`, `/oidc/userinfo`
- one registered client (the homeserver), configured from env, not dynamic
  registration
- `sub` is the OxiCloud user UUID, **never the username**. Usernames can be
  renamed (`username-lowercase.md`), and a Matrix ID that follows a rename
  breaks every room membership.
- the login page **is** the existing OxiCloud login (OPAQUE, magic link,
  upstream OIDC, DPoP-bound session). The homeserver never sees a credential.

The Matrix localpart is derived once at first login (from the username,
sanitised to the Matrix grammar) and is **immutable** afterwards. The mapping
`user_id ↔ mxid` lives in OxiCloud (`chat.matrix_accounts`). Rename in
OxiCloud = display-name change in Matrix, never an MXID change.

**Scope gate.** Only internal users may complete the OIDC flow for the
homeserver client. External/OCM shadow users (`is_external = true`) get the
standard audit-logged refusal:
`event = "oidc_provider.rejected", reason = "external_user"`. This is a
*scope* question (the principal kind), so it's enforced at the authorize
endpoint and pinned in `tests/api/external_users.hurl`, with both the refusal
and an internal user succeeding.

This OP surface is useful beyond Matrix: WOPI hosts, Grafana and other
self-hosted apps can use it too. Keep it generic and don't name it after
Matrix.

### 2. User lifecycle

The homeserver creates the account on first OIDC login (JIT). OxiCloud owns
the lifecycle after that, through the MAS-compatible provisioning API (`/_synapse/mas/*`, see open question 4):

| OxiCloud event | Homeserver action |
|---|---|
| user disabled | deactivate sessions (logout all devices); account kept |
| user re-enabled | nothing (next login works) |
| user deleted | deactivate account (`erase = false` by default; erase is an explicit admin option) |
| display name / avatar change | profile update |

These run as **jobs**, not inline calls. A homeserver that's down must not
fail a user deletion in OxiCloud, and must not let it report success while
leaving an active Matrix session behind. The job pauses at its cursor and
retries (`jobs-handling-recoverable-error.md`).

### 3. Files into chat

Two paths, and both must be clear in the UI:

- **Attach (copy):** a normal Matrix upload into the homeserver media repo. In
  an E2EE room it's encrypted client-side, and OxiCloud never sees it. Counts
  against a homeserver media quota, not the OxiCloud storage quota. Needed for
  federation and E2EE, and it's what every Matrix client does by default.
- **Share (reference):** from the OxiCloud SPA, "Share to chat room" creates a
  grant for the room's **current local members** and posts a message with an
  OxiCloud link. Membership changes are delivered to the appservice (seam 4),
  which adds or revokes grants as people join or leave. Remote (federated)
  members get nothing automatically. Sharing to them goes through OCM, and
  that's out of scope here.

The grant work goes through the existing service layer (`_with_perms`,
`authz.require`). The appservice handler only authenticates the homeserver
(`hs_token`) and calls the service. Membership-synced grants carry a source
tag so a manual grant on the same resource is never revoked by a room leave.

### 4. Appservice: notifications and room events

OxiCloud registers as an **appservice** with a narrow namespace (only the
`@oxicloud:<server>` bot user, no user or alias namespace claims). It
receives:

- membership events in rooms where a file share was posted (for grant sync)
- invites and DMs to local users, which become rows in `notif.notifications`
  plus a `user:{u}:notifications` bus poke, so the bell shows "Alice invited
  you to *Project X*". Only **metadata** is used. E2EE message bodies are
  unreadable and that's not worked around.

It does **not** mirror messages into PostgreSQL. The homeserver is the source
of truth for chat. Duplicating it creates a second consistency problem and
leaks plaintext the E2EE design keeps away from the server.

### 5. Calls: MatrixRTC token endpoint

OxiCloud serves the endpoint `lk-jwt-service` would (`/sfu/get` and
`/get_token`, per MSC4195):

1. The client presents a Matrix OpenID token.
2. OxiCloud validates it against the issuing homeserver's
   `/_matrix/federation/v1/openid/userinfo`. Local tokens go to the sidecar.
   Remote tokens are only honoured when federation is on **and** calls for
   remote users are allowed (an operator switch, off by default, because
   remote users then consume our SFU).
3. OxiCloud mints a LiveKit JWT scoped to the one call room, with a short TTL.

Every refusal is audit-logged (`event = "matrixrtc.token_rejected"`, with
reasons `invalid_openid_token`, `remote_calls_disabled`, `federation_disabled`).
Implementation: the `livekit-api` crate (Apache-2.0) or a hand-rolled
JWT using the `jsonwebtoken` dependency we already have.

### 6. Well-known and discovery

OxiCloud generates `/.well-known/matrix/client` (homeserver base URL, MatrixRTC
foci) and `/.well-known/matrix/server` (only when federation is on). One
source of truth for the public hostname, which today lives in `AppConfig`.

### 7. Web client in the SPA

**Open question, decided in phase 2.** Options:

- **Link out** to a separately served web client. Element Web and Cinny are
  both AGPL, which is fine as a separate app the operator chooses to run, but
  we don't bundle it.
- **A native Svelte chat view** on `matrix-js-sdk` or `matrix-rust-sdk` via
  WASM (both Apache-2.0), vendored and lazy-loaded per the frontend
  dependency rule. This is the only option that gives true integration
  (chat side panel next to a document, "discuss this file"), but it means
  E2EE key management in the browser, which is a large and security-critical
  body of work.

The recommendation was to link out first and decide on the native view once
seams 1–6 are proven.

**Decided 2026-11-12: native view, with E2EE.** The `/chat` page runs
`matrix-js-sdk` (Apache-2.0) with its Rust crypto (`matrix-sdk-crypto-wasm`,
Apache-2.0), both loaded only when the page opens: about 850 KB of JS and a
7.8 MB WASM module (1.4 MB brotli). Without E2EE the page could not read any
DM started in Element, which encrypts DMs by default. Shape of the first cut:

- `OXICLOUD_ENABLE_CHAT` + `OXICLOUD_CHAT_HOMESERVER_URL`, published in
  `/api/config` as `features.chat` and `chat.homeserver_url`.
- API calls go to `/_matrix/client/*` on **OxiCloud's origin**, forwarded to
  the homeserver by the reverse proxy. The SPA's CSP is fixed at build time
  with `connect-src 'self'`, and a runtime homeserver origin can't be added
  to it.
- Sign-in navigates to the homeserver's SSO redirect (OxiCloud is its IdP,
  consent skipped) and comes back to `/chat?loginToken=…`. The homeserver
  must trust the OxiCloud host as a redirect target
  (`oidc_registration_allowed_redirect_hosts`) or it shows a confirmation
  page.
- The Matrix session is stored per OxiCloud user in `localStorage`; the
  crypto store is IndexedDB, keyed by Matrix device. OxiCloud logout logs the
  device out of the homeserver and wipes both.
- Encryption: unlock with an existing recovery key (cross-signs the device,
  restores the key backup), or set up cross-signing, secret storage and key
  backup for an account that has none. Interactive (emoji) verification is
  not in the first cut.
- Not yet: media (attachments show as their file name), replies, edits,
  reactions, typing, threads, room settings, calls.

## Federation

- Off by default: no `/.well-known/matrix/server`, and the federation listener
  isn't routed. The instance is a closed Matrix island that still works fully
  for its own users and clients.
- On: the operator sets it in config, and it's documented with its
  consequences (public server key, remote media caching, abuse handling,
  storage growth from joined public rooms). Plan for a per-instance allowlist
  and denylist of remote servers (homeserver ACL config).
- This is the chat counterpart to OCM. An OxiCloud-to-OxiCloud mesh then
  federates files (OCM) and chat (Matrix) between the same instances.

## Resilience and operations

- **Backups.** The homeserver keeps its state in **RocksDB on disk, not in
  PostgreSQL**. [`backup-and-restore.md`](./backup-and-restore.md) must cover
  it, or a restore silently loses every conversation, which breaks the "no
  data loss" axis. RocksDB needs either its checkpoint API or a stopped
  homeserver for a consistent snapshot. Copying files from a running instance
  is not a backup. The bundle format gets a `matrix/` section, and restore
  refuses a bundle whose homeserver section is missing when chat is enabled.
- **E2EE key loss is data loss to the user.** Document server-side key backup
  (encrypted with the user's recovery key) in the user docs. The server
  can't recover keys and must not pretend it can.
- **Failure is loud.** If the homeserver is unreachable, the admin dashboard
  says so and lifecycle jobs pause. Nothing reports success.
- **Packaging.** `docker-compose.yml` gains `homeserver` and `livekit`
  services behind a profile (`--profile chat`), disabled by default. The
  bundled single-binary distribution (`bundled-binary.md`) doesn't include
  chat. Its docs point at the compose profile.
- **Feature flag.** `OXICLOUD_ENABLE_CHAT` in `FeaturesConfig`. When it's off,
  OxiCloud serves no Matrix well-known, the OP still exists for other clients,
  and the appservice routes return 404.
- **Scale.** 10k users is comfortably inside the conduwuit-lineage design
  envelope. LiveKit scales by SFU node, and one node handles typical
  enterprise call loads. Measure in phase 0. Don't assume.

## Security

- The homeserver ↔ OxiCloud secrets (`as_token`, `hs_token`, admin API token,
  OIDC client secret, LiveKit API key/secret) come from env or files, are
  never logged, and are generated by the setup script rather than shipped as
  defaults.
- The appservice endpoints are authenticated by `hs_token` only and routed
  only on the internal network listener. They're never reachable from the
  public reverse proxy.
- The OP authorize endpoint reuses the existing session, CSRF and DPoP
  machinery. No second login implementation.
- Refusals are audit-logged at every seam (`oidc_provider.rejected`,
  `matrixrtc.token_rejected`, `chat_share.rejected`).

## Phases

| Phase | Deliverable | Exit criterion |
|---|---|---|
| **0 — bench** | `tools/matrix-bench/`: Tuwunel + LiveKit + `lk-jwt-service` + Dex as a throwaway IdP behind Caddy. Run Element X iOS and Android through login, E2EE DM, group room, background push, 1:1 and 4-person call. Repeat with Continuwuity. | Homeserver chosen. Every *verify* in this doc resolved. Measured RAM/CPU at a synthetic 1k-user load. |
| **1 — identity** | OxiCloud OIDC provider (seam 1), user lifecycle jobs (seam 2), well-known (seam 6), `OXICLOUD_ENABLE_CHAT`, compose profile. | Element X logs in with an OxiCloud account. Disable/delete propagates. Hurl pins for OP endpoints and the external-user refusal. |
| **2 — calls** | MatrixRTC token endpoint (seam 5), drop `lk-jwt-service` from the bench. | Element X group call through OxiCloud-issued tokens. Refusal paths pinned. |
| **3 — collaboration** | Appservice (seam 4), "share to room" (seam 3), bell notifications. Decide on the web client (seam 7). | Sharing a folder to a room grants current members and revokes on leave. Integration test for the membership → grant sync. |
| **4 — federation** | Federation switch, server ACL config, operator docs. | Two OxiCloud instances federate a room and a call. |
| **5 — backup** | Homeserver section in the backup bundle. | Restore drill with chat history verified. |

Phase 5 has to land **before chat is announced as production-ready**, even
though it's numbered last.

## Open questions

1. ~~Continuwuity's licence.~~ **Apache-2.0** (repository LICENSE file).
2. ~~`livekit-api` crate.~~ **Apache-2.0**, actively released (0.10.1, 2026-11-04).
3. ~~QR-code device login.~~ **Yes.** Tuwunel's `[global.rendezvous]`
   (MSC4108/MSC4388) is on by default whenever the built-in OIDC server runs.
   Sessions are in memory, so a restart drops a scan in progress. The reverse
   proxy must not compress rendezvous responses.
4. ~~Logout all devices without erasing.~~ **Yes, via an HTTP API, not admin-room
   commands.** Tuwunel implements Synapse's MAS provisioning API under
   `/_synapse/mas/*`, bearer-authenticated by `mas_secret`: `provision_user`,
   `query_user`, `is_localpart_available`, `delete_user {erase}`,
   `reactivate_user`, `set_displayname`/`unset_displayname`,
   `sync_devices`, `upsert_device`, `delete_device`,
   `update_device_display_name`, `allow_cross_signing_reset`.
   `sync_devices` with an empty list removes every device; `delete_user`
   with `erase = false` deactivates. Seam 2 uses this API, and it must never
   be routed publicly.
5. ~~Media quota.~~ **None** in Tuwunel (no quota code in the tree as of
   v1.9.4). The media repo grows unbounded. Either accept that and monitor
   it, or enforce it upstream (contribute a quota, or cap with
   `max_request_size` only). Decide in phase 3.
6. ~~Web client: link out vs native Svelte view (seam 7).~~ **Native, with E2EE** (see seam 7).
7. Guest access and public rooms: allow, or local users only?

### Findings that change seam 1 (identity mapping)

Tuwunel maps an upstream login to a Matrix user in two stages
(`src/api/client/session/sso.rs`, v1.9.4):

- **First login:** the localpart is taken from the first claim that yields
  a free (or, with `trusted = true`, matching) user. The order is `sub` (only
  if listed in `userid_claims`), `preferred_username`, `username`,
  `nickname`, then the email localpart. `unique_id_fallbacks = false` makes a
  conflict an error instead of a random ID.
- **Every later login:** matched by the stored (issuer, `sub`) association,
  not by claims.

So OxiCloud's OP sends `sub = <user UUID>` and
`preferred_username = <immutable localpart from chat.matrix_accounts>`, and
configures `userid_claims = ["preferred_username"]`,
`unique_id_fallbacks = false`. A rename in OxiCloud never moves the MXID, and
no pre-provisioning call is needed. `trusted = true` is still required so
that an account already provisioned through `/_synapse/mas/provision_user`
(e.g. created by an admin before first login) is adopted rather than refused.
That's safe because OxiCloud controls the claim.

### Findings for resilience

Tuwunel has online backups (`[global.database.backup]`, using the RocksDB
backup engine, triggered by `!admin server backup-database` or `SIGUSR2`
with `admin.signal_execute`), and restores with `--restore-backup`.
**Media is not included** and needs its own copy. Phase 5 builds on this
instead of filesystem snapshots.

### Version note

Tuwunel v2.0.0 was released on 2026-11-10 and renames much of the config
(sectioned keys such as `[global.authentication.oidc] native_auth` and
`[global.http.listen]`). The phase-0 bench pins **v1.9.4**. Move to 2.x
after it has had a few weeks of patch releases, and re-run the bench
checklist when you do.

## References

- Tuwunel — https://github.com/matrix-construct/tuwunel (README; 1.5.0 OIDC
  client, 1.6.0 native OAuth server, 1.9.x `oidc_native_auth` notes)
- Continuwuity — https://continuwuity.org/guides/oidc ,
  https://continuwuity.org/calls/livekit
- `lk-jwt-service` (AGPL-3.0, reference behaviour only) —
  https://github.com/element-hq/lk-jwt-service
- MSC3861 next-gen auth — https://github.com/matrix-org/matrix-spec-proposals/pull/3861
- MSC4143 (MatrixRTC transports), MSC4186 (Simplified Sliding Sync),
  MSC4195 (LiveKit backend), MSC4108 (QR login)
