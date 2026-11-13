# =============================================================
# OxiCloud — step-up re-authentication ("confirm it's you")
# =============================================================
# docs/plan/passkeys.md, Phase 2a. Changing how an account signs in
# (adding or removing a passkey) needs a session whose user proved who
# they are in the last 10 minutes; otherwise 403 `ReauthRequired`, which
# the SPA turns into a "Confirm it's you" dialog.
#
# A fresh login counts as proof. A device-flow session does not (the
# device never proved anything; the approving browser did), which gives
# this file a stale session without waiting 10 minutes:
#
#   • the gate refuses the stale session, and lets the same session
#     through once it confirms with the password — a gate that refused
#     everyone would pass the refusal alone;
#   • a wrong password confirms nothing, and answers like a wrong login;
#   • GET /api/auth/reauth tells the SPA which methods the user has.
# =============================================================


# ── Signed-in only (before any login: Hurl keeps the cookies) ──
GET {{base_url}}/api/auth/reauth

HTTP 401

POST {{base_url}}/api/auth/reauth/password
Content-Type: application/json
{ "password": "x" }

HTTP 401


# ── Fresh login passes the gate ──────────────────────────────
POST {{base_url}}/api/auth/login
Content-Type: application/json
{ "username": "{{username}}", "password": "{{password}}" }

HTTP 200
[Captures]
admin_token: jsonpath "$.access_token"

GET {{base_url}}/api/auth/reauth
Authorization: Bearer {{admin_token}}

HTTP 200
[Asserts]
jsonpath "$.password" == true
jsonpath "$.passkey" == false
jsonpath "$.window_minutes" == 10

POST {{base_url}}/api/auth/passkeys/register/start
Authorization: Bearer {{admin_token}}

HTTP 200
[Asserts]
jsonpath "$.ceremonyId" isString


# ── A device-flow session starts stale ───────────────────────
POST {{base_url}}/api/auth/device/authorize
Content-Type: application/json
{ "client_name": "hurl-step-up", "scope": "webdav" }

HTTP 200
[Captures]
step_up_device_code: jsonpath "$.device_code"
step_up_user_code: jsonpath "$.user_code"

POST {{base_url}}/api/auth/device/verify
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{ "user_code": "{{step_up_user_code}}", "action": "approve" }

HTTP 200

POST {{base_url}}/api/auth/device/token
Content-Type: application/json
{
  "device_code": "{{step_up_device_code}}",
  "grant_type":  "urn:ietf:params:oauth:grant-type:device_code"
}

HTTP 200
[Captures]
device_token: jsonpath "$.access_token"


# Refused: the gate, not the passkey service, answers.
POST {{base_url}}/api/auth/passkeys/register/start
Authorization: Bearer {{device_token}}

HTTP 403
[Asserts]
jsonpath "$.error_type" == "ReauthRequired"

DELETE {{base_url}}/api/auth/passkeys/00000000-0000-4000-8000-000000000000
Authorization: Bearer {{device_token}}

HTTP 403
[Asserts]
jsonpath "$.error_type" == "ReauthRequired"

# Listing and renaming are not gated.
GET {{base_url}}/api/auth/passkeys
Authorization: Bearer {{device_token}}

HTTP 200


# ── Confirming ───────────────────────────────────────────────
# Wrong password: same shape as a failed login, and the gate stays shut.
POST {{base_url}}/api/auth/reauth/password
Authorization: Bearer {{device_token}}
Content-Type: application/json
{ "password": "definitely-not-the-password" }

HTTP 401
[Asserts]
jsonpath "$.error_type" == "InvalidCredentials"

POST {{base_url}}/api/auth/passkeys/register/start
Authorization: Bearer {{device_token}}

HTTP 403

# Right password: the same session now passes.
POST {{base_url}}/api/auth/reauth/password
Authorization: Bearer {{device_token}}
Content-Type: application/json
{ "password": "{{password}}" }

HTTP 204

POST {{base_url}}/api/auth/passkeys/register/start
Authorization: Bearer {{device_token}}

HTTP 200
[Asserts]
jsonpath "$.ceremonyId" isString

# Removing still answers for the passkey itself once past the gate.
DELETE {{base_url}}/api/auth/passkeys/00000000-0000-4000-8000-000000000000
Authorization: Bearer {{device_token}}

HTTP 404


# ── Passkey confirmation needs a passkey ─────────────────────
# The admin has none: refused like a wrong password.
POST {{base_url}}/api/auth/reauth/passkey/start
Authorization: Bearer {{admin_token}}

HTTP 401
[Asserts]
jsonpath "$.error_type" == "InvalidCredentials"
