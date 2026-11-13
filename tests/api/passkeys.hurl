# =============================================================
# OxiCloud — Passkey (WebAuthn) endpoints: discovery, shapes, refusals
# =============================================================
# docs/plan/passkeys.md, Phase 1. A complete register + sign-in needs an
# authenticator; that round trip is pinned in Rust against a software
# authenticator (application/services/passkey_service_test.rs). What
# this file pins is the wire contract the SPA depends on and every
# refusal that needs no authenticator:
#
#   • /api/config advertises `features.passkeys` (true here: run.sh sets
#     OXICLOUD_BASE_URL to a `localhost` URL, and WebAuthn refuses IP
#     hosts as a relying party, so without it the service stays off).
#   • Option shapes handed to navigator.credentials: base64url strings,
#     RP id from the public URL, user verification required, discoverable
#     sign-in with an empty allow list.
#   • Signed-in routes refuse anonymous callers.
#   • An unknown ceremony id never registers anything and never signs in;
#     sign-in refusals all collapse to 401 InvalidCredentials.
#   • Another user's (or a made-up) passkey id is 404, never 403.
# =============================================================


# ── Discovery ────────────────────────────────────────────────
GET {{base_url}}/api/config

HTTP 200
[Asserts]
jsonpath "$.features.passkeys" == true


# ── Signed-in routes need a session ──────────────────────────
GET {{base_url}}/api/auth/passkeys

HTTP 401

POST {{base_url}}/api/auth/passkeys/register/start

HTTP 401


# ── Admin session for the rest ───────────────────────────────
POST {{base_url}}/api/auth/login
Content-Type: application/json
{ "username": "{{username}}", "password": "{{password}}" }

HTTP 200
[Captures]
admin_token: jsonpath "$.access_token"


GET {{base_url}}/api/auth/passkeys
Authorization: Bearer {{admin_token}}

HTTP 200
[Asserts]
jsonpath "$" isCollection


# ── Registration options ─────────────────────────────────────
# The SPA decodes `challenge`, `user.id` and `excludeCredentials[].id`
# from base64url; the RP id must be the public URL's host or every
# browser refuses the ceremony.
POST {{base_url}}/api/auth/passkeys/register/start
Authorization: Bearer {{admin_token}}

HTTP 200
[Asserts]
jsonpath "$.ceremonyId" isString
jsonpath "$.options.publicKey.challenge" isString
jsonpath "$.options.publicKey.challenge" matches "^[A-Za-z0-9_-]+$"
jsonpath "$.options.publicKey.rp.id" == "localhost"
jsonpath "$.options.publicKey.user.id" isString
jsonpath "$.options.publicKey.authenticatorSelection.residentKey" == "preferred"
jsonpath "$.options.publicKey.authenticatorSelection.userVerification" == "required"


# An unknown ceremony registers nothing, even with a well-formed body.
POST {{base_url}}/api/auth/passkeys/register/finish
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{
  "ceremonyId": "00000000-0000-4000-8000-000000000000",
  "name": "Hurl",
  "credential": {
    "id": "AA",
    "rawId": "AA",
    "type": "public-key",
    "response": { "attestationObject": "AA", "clientDataJSON": "AA" }
  }
}

HTTP 400
[Asserts]
jsonpath "$.error_type" == "PasskeyVerificationFailed"


# ── Rename / remove: names validated, ids scoped to the caller ──
PATCH {{base_url}}/api/auth/passkeys/00000000-0000-4000-8000-000000000000
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{ "name": "   " }

HTTP 400
[Asserts]
jsonpath "$.error_type" == "PasskeyInvalidName"

PATCH {{base_url}}/api/auth/passkeys/00000000-0000-4000-8000-000000000000
Authorization: Bearer {{admin_token}}
Content-Type: application/json
{ "name": "Laptop" }

HTTP 404

DELETE {{base_url}}/api/auth/passkeys/00000000-0000-4000-8000-000000000000
Authorization: Bearer {{admin_token}}

HTTP 404


# ── Sign-in (public) ─────────────────────────────────────────
# Discoverable: no username, empty allow list, the browser offers the
# account.
POST {{base_url}}/api/auth/passkey/login/start

HTTP 200
[Asserts]
jsonpath "$.ceremonyId" isString
jsonpath "$.options.publicKey.challenge" matches "^[A-Za-z0-9_-]+$"
jsonpath "$.options.publicKey.allowCredentials" count == 0
jsonpath "$.options.publicKey.userVerification" == "required"


# Unknown ceremony → the same 401 as a wrong password; the reason is in
# the audit log (`passkey.login_rejected`, reason=ceremony_expired).
POST {{base_url}}/api/auth/passkey/login/finish
Content-Type: application/json
{
  "ceremonyId": "00000000-0000-4000-8000-000000000000",
  "credential": {
    "id": "AA",
    "rawId": "AA",
    "type": "public-key",
    "response": {
      "authenticatorData": "AA",
      "clientDataJSON": "AA",
      "signature": "AA",
      "userHandle": null
    }
  }
}

HTTP 401
[Asserts]
jsonpath "$.error_type" == "InvalidCredentials"
