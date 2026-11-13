# =============================================================
# OxiCloud — recovery codes
# =============================================================
# docs/plan/passkeys.md, Phase 2a. The way back into an account whose
# passkeys are gone: ten single-use codes, shown once, a new set retires
# the old one. Pins:
#
#   • status and generation are signed-in; sign-in with a code is public
#     and every refusal is the same 401 InvalidCredentials;
#   • a code signs in once, only for its own account, and the session it
#     makes is fresh (it can add a passkey without confirming again);
#   • generating is behind the step-up gate: refused for a stale
#     (device-flow) session, allowed for a fresh one;
#   • a new set retires the old codes.
# Normalisation of typed codes (case, spaces) is pinned in Rust
# (recovery_code_service_test.rs).
# =============================================================


# ── Before any login (Hurl keeps the cookies) ────────────────
GET {{base_url}}/api/auth/recovery-codes

HTTP 401

POST {{base_url}}/api/auth/recovery/login
Content-Type: application/json
{ "username": "{{username}}", "code": "AAAA-AAAA-AAAA-AAAA" }

HTTP 401
[Asserts]
jsonpath "$.error_type" == "InvalidCredentials"


POST {{base_url}}/api/auth/login
Content-Type: application/json
{ "username": "{{username}}", "password": "{{password}}" }

HTTP 200
[Captures]
admin_token: jsonpath "$.access_token"


# ── Make a set ───────────────────────────────────────────────
POST {{base_url}}/api/auth/recovery-codes
Authorization: Bearer {{admin_token}}

HTTP 200
[Captures]
code_a: jsonpath "$.codes[0]"
code_b: jsonpath "$.codes[1]"
[Asserts]
jsonpath "$.codes" count == 10
jsonpath "$.codes[0]" matches "^[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}$"

GET {{base_url}}/api/auth/recovery-codes
Authorization: Bearer {{admin_token}}

HTTP 200
[Asserts]
jsonpath "$.remaining" == 10
jsonpath "$.generated_at" isString


# ── Sign in with a code ──────────────────────────────────────
# Another account's name: refused, and the code is not used up.
POST {{base_url}}/api/auth/recovery/login
Content-Type: application/json
{ "username": "no-such-user-recovery", "code": "{{code_a}}" }

HTTP 401
[Asserts]
jsonpath "$.error_type" == "InvalidCredentials"

POST {{base_url}}/api/auth/recovery/login
Content-Type: application/json
{ "username": "{{username}}", "code": "{{code_a}}" }

HTTP 200
[Captures]
recovered_token: jsonpath "$.access_token"
[Asserts]
jsonpath "$.access_token" isString

# Single use.
POST {{base_url}}/api/auth/recovery/login
Content-Type: application/json
{ "username": "{{username}}", "code": "{{code_a}}" }

HTTP 401

# The recovered session is fresh: it may add a passkey at once.
POST {{base_url}}/api/auth/passkeys/register/start
Authorization: Bearer {{recovered_token}}

HTTP 200

GET {{base_url}}/api/auth/recovery-codes
Authorization: Bearer {{recovered_token}}

HTTP 200
[Asserts]
jsonpath "$.remaining" == 9


# ── Generating needs a fresh session ─────────────────────────
POST {{base_url}}/api/auth/device/authorize
Content-Type: application/json
{ "client_name": "hurl-recovery-codes", "scope": "webdav" }

HTTP 200
[Captures]
rc_device_code: jsonpath "$.device_code"
rc_user_code: jsonpath "$.user_code"

POST {{base_url}}/api/auth/device/verify
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{ "user_code": "{{rc_user_code}}", "action": "approve" }

HTTP 200

POST {{base_url}}/api/auth/device/token
Content-Type: application/json
{
  "device_code": "{{rc_device_code}}",
  "grant_type":  "urn:ietf:params:oauth:grant-type:device_code"
}

HTTP 200
[Captures]
stale_token: jsonpath "$.access_token"

POST {{base_url}}/api/auth/recovery-codes
Authorization: Bearer {{stale_token}}

HTTP 403
[Asserts]
jsonpath "$.error_type" == "ReauthRequired"

# Reading the count is not gated.
GET {{base_url}}/api/auth/recovery-codes
Authorization: Bearer {{stale_token}}

HTTP 200


# ── A new set retires the old one ────────────────────────────
POST {{base_url}}/api/auth/recovery-codes
Authorization: Bearer {{admin_token}}

HTTP 200
[Asserts]
jsonpath "$.codes" count == 10

POST {{base_url}}/api/auth/recovery/login
Content-Type: application/json
{ "username": "{{username}}", "code": "{{code_b}}" }

HTTP 401
