# =============================================================
# OxiCloud — Nextcloud Login Flow v2: "continue as the signed-in user"
# =============================================================
# docs/plan/passkeys.md, Phase 2a. An account without a password (passkey
# only) cannot type one into the client's grant page, so the page offers
# the browser's session instead: POST /api/nextcloud/login-flow/{token}/grant.
#
# Pins:
#   • signed-in only; an unknown or used flow is 404 LoginFlowNotFound;
#   • a fresh session links the client: the poll then hands it an app
#     password for this account (the same completion the password path
#     uses), and that password opens WebDAV;
#   • the grant mints a long-lived credential, so a stale session (device
#     flow, see step_up.hurl) gets 403 ReauthRequired, and passes after
#     confirming — a gate that refused everyone would pass the refusal.
#
# Runs before the shared-drive scenarios, so the admin has one drive and
# the grant completes without the picker (the picker branch shares
# `advance_flow` with the password path, pinned in
# nc_login_flow_v2_drive_picker.hurl).
# =============================================================


# ── Signed-in only (before any login: Hurl keeps the cookies) ──
POST {{base_url}}/api/nextcloud/login-flow/abc123/grant

HTTP 401


POST {{base_url}}/api/auth/login
Content-Type: application/json
{ "username": "{{username}}", "password": "{{password}}" }

HTTP 200
[Captures]
admin_token: jsonpath "$.access_token"


# ── Unknown flow ─────────────────────────────────────────────
POST {{base_url}}/api/nextcloud/login-flow/0123456789abcdef/grant
Authorization: Bearer {{admin_token}}

HTTP 404
[Asserts]
jsonpath "$.error_type" == "LoginFlowNotFound"


# ── A client starts a flow; the signed-in user grants it ─────
POST {{base_url}}/index.php/login/v2

HTTP 200
[Captures]
poll_token: jsonpath "$.poll.token"
flow_token: jsonpath "$.login" regex "/login/v2/flow/([0-9a-fA-F]+)"

POST {{base_url}}/api/nextcloud/login-flow/{{flow_token}}/grant
Authorization: Bearer {{admin_token}}

HTTP 200
[Asserts]
jsonpath "$.redirect" endsWith "/nextcloud/success"
jsonpath "$.drives" not exists

# The client's poll now gets an app password for this account.
POST {{base_url}}/login/v2/poll
[FormParams]
token: {{poll_token}}

HTTP 200
[Captures]
app_password: jsonpath "$.appPassword"
[Asserts]
jsonpath "$.loginName" == "{{username}}"
jsonpath "$.appPassword" isString

# ...and it works.
PROPFIND {{base_url}}/remote.php/dav/files/{{username}}/
Depth: 0
[BasicAuth]
{{username}}: {{app_password}}

HTTP 207

# The flow is used up.
POST {{base_url}}/api/nextcloud/login-flow/{{flow_token}}/grant
Authorization: Bearer {{admin_token}}

HTTP 404


# ── A stale session must confirm first ───────────────────────
POST {{base_url}}/api/auth/device/authorize
Content-Type: application/json
{ "client_name": "hurl-nc-session-grant", "scope": "webdav" }

HTTP 200
[Captures]
nc_device_code: jsonpath "$.device_code"
nc_user_code: jsonpath "$.user_code"

POST {{base_url}}/api/auth/device/verify
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{ "user_code": "{{nc_user_code}}", "action": "approve" }

HTTP 200

POST {{base_url}}/api/auth/device/token
Content-Type: application/json
{
  "device_code": "{{nc_device_code}}",
  "grant_type":  "urn:ietf:params:oauth:grant-type:device_code"
}

HTTP 200
[Captures]
stale_token: jsonpath "$.access_token"

POST {{base_url}}/index.php/login/v2

HTTP 200
[Captures]
flow_token_2: jsonpath "$.login" regex "/login/v2/flow/([0-9a-fA-F]+)"

POST {{base_url}}/api/nextcloud/login-flow/{{flow_token_2}}/grant
Authorization: Bearer {{stale_token}}

HTTP 403
[Asserts]
jsonpath "$.error_type" == "ReauthRequired"

POST {{base_url}}/api/auth/reauth/password
Authorization: Bearer {{stale_token}}
Content-Type: application/json
{ "password": "{{password}}" }

HTTP 204

POST {{base_url}}/api/nextcloud/login-flow/{{flow_token_2}}/grant
Authorization: Bearer {{stale_token}}

HTTP 200
[Asserts]
jsonpath "$.redirect" endsWith "/nextcloud/success"
