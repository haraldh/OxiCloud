# =============================================================
# OxiCloud — removing the account password
# =============================================================
# docs/plan/passkeys.md, Phase 2a step 4. DELETE /api/auth/password turns
# an account into a passkey-only one. Refused unless it keeps a way back
# (two passkeys, or a passkey plus recovery codes), and only from a
# session that confirmed it's the user recently.
#
# Hurl has no authenticator, so the success path is pinned below the
# HTTP layer: password_removal_service_test.rs (the rules) and the
# integration tests in passkey_pg_repository.rs (hash and OPAQUE envelope
# cleared together, federated rows untouched). This file pins the doors:
#   • signed-in only, behind the step-up gate (stale device-flow session
#     → 403 ReauthRequired);
#   • no passkey → 409 PasswordRemovalNeedsBackup, and recovery codes
#     alone do not change that;
#   • a refused removal leaves the password working.
# =============================================================


# ── Before any login (Hurl keeps the cookies) ────────────────
DELETE {{base_url}}/api/auth/password

HTTP 401


POST {{base_url}}/api/auth/login
Content-Type: application/json
{ "username": "{{username}}", "password": "{{password}}" }

HTTP 200
[Captures]
admin_token: jsonpath "$.access_token"


# ── Not enough to fall back on ───────────────────────────────
DELETE {{base_url}}/api/auth/password
Authorization: Bearer {{admin_token}}

HTTP 409
[Asserts]
jsonpath "$.error_type" == "PasswordRemovalNeedsBackup"

POST {{base_url}}/api/auth/recovery-codes
Authorization: Bearer {{admin_token}}

HTTP 200

# Recovery codes without a passkey are still not enough.
DELETE {{base_url}}/api/auth/password
Authorization: Bearer {{admin_token}}

HTTP 409
[Asserts]
jsonpath "$.error_type" == "PasswordRemovalNeedsBackup"


# ── Behind the step-up gate ──────────────────────────────────
POST {{base_url}}/api/auth/device/authorize
Content-Type: application/json
{ "client_name": "hurl-password-removal", "scope": "webdav" }

HTTP 200
[Captures]
pr_device_code: jsonpath "$.device_code"
pr_user_code: jsonpath "$.user_code"

POST {{base_url}}/api/auth/device/verify
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{ "user_code": "{{pr_user_code}}", "action": "approve" }

HTTP 200

POST {{base_url}}/api/auth/device/token
Content-Type: application/json
{
  "device_code": "{{pr_device_code}}",
  "grant_type":  "urn:ietf:params:oauth:grant-type:device_code"
}

HTTP 200
[Captures]
stale_token: jsonpath "$.access_token"

DELETE {{base_url}}/api/auth/password
Authorization: Bearer {{stale_token}}

HTTP 403
[Asserts]
jsonpath "$.error_type" == "ReauthRequired"


# ── The password still works ─────────────────────────────────
POST {{base_url}}/api/auth/login
Content-Type: application/json
{ "username": "{{username}}", "password": "{{password}}" }

HTTP 200
