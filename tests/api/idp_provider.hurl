# =============================================================
# OxiCloud as OpenID Provider — authorization-code + PKCE flow
# =============================================================
# Pins the wire contract a relying party (first of all the Matrix
# homeserver, docs/plan/chat-matrix.md § seam 1) depends on:
# discovery, the authorize → SPA consent → code → token → userinfo
# chain, and every refusal a regression could quietly turn into an
# accept: open redirect on an unregistered redirect_uri, code replay,
# a wrong client secret, a revoked access token.
#
# Client `hurl` is configured in tests/common/server.env.
# PKCE uses the RFC 7636 Appendix B vector.
# The external-user refusal lives in external_users.hurl, next to the
# other principal-kind gates.
# =============================================================


# ─────────────────────────────────────────────────────────────
# Discovery + JWKS. Tuwunel discovers every endpoint from here and
# refuses a mismatched `issuer`, so the endpoint URLs are pinned.
# ─────────────────────────────────────────────────────────────
GET {{base_url}}/.well-known/openid-configuration

HTTP 200
[Asserts]
jsonpath "$.authorization_endpoint" endsWith "/oidc/authorize"
jsonpath "$.token_endpoint" endsWith "/oidc/token"
jsonpath "$.userinfo_endpoint" endsWith "/oidc/userinfo"
jsonpath "$.jwks_uri" endsWith "/oidc/jwks"
jsonpath "$.code_challenge_methods_supported" contains "S256"
jsonpath "$.code_challenge_methods_supported" not contains "plain"
jsonpath "$.token_endpoint_auth_methods_supported" contains "client_secret_post"
jsonpath "$.id_token_signing_alg_values_supported[0]" == "ES256"
[Captures]
issuer: jsonpath "$.issuer"

GET {{base_url}}/oidc/jwks

HTTP 200
[Asserts]
jsonpath "$.keys[0].kty" == "EC"
jsonpath "$.keys[0].crv" == "P-256"
jsonpath "$.keys[0].alg" == "ES256"
jsonpath "$.keys[0].d" not exists


# ─────────────────────────────────────────────────────────────
# Untrusted client / redirect: 400 page, NEVER a redirect. A 302
# here would make the provider an open redirector.
# ─────────────────────────────────────────────────────────────
GET {{base_url}}/oidc/authorize
[Query]
client_id: nope
redirect_uri: http://localhost:9/cb
response_type: code
scope: openid
code_challenge: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
code_challenge_method: S256

HTTP 400
[Asserts]
header "Location" not exists

GET {{base_url}}/oidc/authorize
[Query]
client_id: hurl
redirect_uri: http://localhost:9/cb/../evil
response_type: code
scope: openid
code_challenge: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
code_challenge_method: S256

HTTP 400
[Asserts]
header "Location" not exists


# ─────────────────────────────────────────────────────────────
# Known client, protocol error: reported back to the client with
# its state. PKCE is mandatory, `plain` is not accepted.
# ─────────────────────────────────────────────────────────────
GET {{base_url}}/oidc/authorize
[Query]
client_id: hurl
redirect_uri: http://localhost:9/cb
response_type: code
scope: openid
state: s-pkce
code_challenge: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
code_challenge_method: plain

HTTP 302
[Asserts]
header "Location" startsWith "http://localhost:9/cb?"
header "Location" contains "error=invalid_request"
header "Location" contains "state=s-pkce"
header "Location" not contains "code="


# ─────────────────────────────────────────────────────────────
# Happy path. authorize → SPA consent page.
# ─────────────────────────────────────────────────────────────
GET {{base_url}}/oidc/authorize
[Query]
client_id: hurl
redirect_uri: http://localhost:9/cb
response_type: code
scope: openid profile email
state: s-ok
nonce: n-ok
code_challenge: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
code_challenge_method: S256

HTTP 302
[Asserts]
header "Location" matches "/oauth/consent/[0-9a-f-]{36}$"
[Captures]
request_id: header "Location" regex "/oauth/consent/([0-9a-f-]{36})$"

# The consent API needs a session. Checked BEFORE logging in: Hurl keeps
# cookies across requests, and the login sets the session cookie.
GET {{base_url}}/api/idp/requests/{{request_id}}

HTTP 401

POST {{base_url}}/api/auth/login
Content-Type: application/json
{ "username": "{{username}}", "password": "{{password}}" }

HTTP 200
[Captures]
token: jsonpath "$.access_token"


GET {{base_url}}/api/idp/requests/{{request_id}}
Authorization: Bearer {{token}}

HTTP 200
[Asserts]
jsonpath "$.client_id" == "hurl"
jsonpath "$.client_name" == "Hurl Test RP"
jsonpath "$.skip_consent" == false
jsonpath "$.scopes" contains "openid"
jsonpath "$.scopes" contains "email"

POST {{base_url}}/api/idp/requests/{{request_id}}/decision
Authorization: Bearer {{token}}
Content-Type: application/json
{ "approve": true }

HTTP 200
[Asserts]
jsonpath "$.redirect_to" startsWith "http://localhost:9/cb?"
jsonpath "$.redirect_to" contains "state=s-ok"
jsonpath "$.redirect_to" contains "iss="
[Captures]
code: jsonpath "$.redirect_to" regex "code=([A-Za-z0-9_-]+)"

# A request is decided once.
POST {{base_url}}/api/idp/requests/{{request_id}}/decision
Authorization: Bearer {{token}}
Content-Type: application/json
{ "approve": true }

HTTP 404


# ─────────────────────────────────────────────────────────────
# Token endpoint. A wrong secret is refused WITHOUT burning the
# code (client auth runs first), so the real exchange still works.
# ─────────────────────────────────────────────────────────────
POST {{base_url}}/oidc/token
[Form]
grant_type: authorization_code
code: {{code}}
redirect_uri: http://localhost:9/cb
code_verifier: dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
client_id: hurl
client_secret: wrong-wrong-wrong-wrong-wrong-wrong-wrong

HTTP 401
[Asserts]
jsonpath "$.error" == "invalid_client"
header "WWW-Authenticate" startsWith "Basic"

POST {{base_url}}/oidc/token
[Form]
grant_type: authorization_code
code: {{code}}
redirect_uri: http://localhost:9/cb
code_verifier: dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
client_id: hurl
client_secret: hurl-idp-secret-do-not-use-in-prod-0123456789

HTTP 200
[Asserts]
header "Cache-Control" == "no-store"
jsonpath "$.token_type" == "Bearer"
jsonpath "$.expires_in" > 0
jsonpath "$.id_token" matches "^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$"
[Captures]
access_token: jsonpath "$.access_token"

# Replay of a used code.
POST {{base_url}}/oidc/token
[Form]
grant_type: authorization_code
code: {{code}}
redirect_uri: http://localhost:9/cb
code_verifier: dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
client_id: hurl
client_secret: hurl-idp-secret-do-not-use-in-prod-0123456789

HTTP 400
[Asserts]
jsonpath "$.error" == "invalid_grant"


# ─────────────────────────────────────────────────────────────
# userinfo. `sub` is the user UUID (never the username: usernames
# are not what a relying party should key accounts on), and
# preferred_username is the frozen handle.
# ─────────────────────────────────────────────────────────────
GET {{base_url}}/oidc/userinfo
Authorization: Bearer {{access_token}}

HTTP 200
[Asserts]
jsonpath "$.sub" matches "^[0-9a-f-]{36}$"
jsonpath "$.preferred_username" == "{{username}}"
jsonpath "$.email" == "{{email}}"
jsonpath "$.email_verified" exists

GET {{base_url}}/oidc/userinfo
Authorization: Bearer not-a-token

HTTP 401
[Asserts]
jsonpath "$.error" == "invalid_token"
header "WWW-Authenticate" contains "invalid_token"

# Revocation (RFC 7009) kills the access token.
POST {{base_url}}/oidc/revoke
[Form]
token: {{access_token}}
client_id: hurl
client_secret: hurl-idp-secret-do-not-use-in-prod-0123456789

HTTP 200

GET {{base_url}}/oidc/userinfo
Authorization: Bearer {{access_token}}

HTTP 401


# ─────────────────────────────────────────────────────────────
# Declining: the client gets access_denied and no code.
# ─────────────────────────────────────────────────────────────
GET {{base_url}}/oidc/authorize
[Query]
client_id: hurl
redirect_uri: http://localhost:9/cb
response_type: code
scope: openid
state: s-deny
code_challenge: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
code_challenge_method: S256

HTTP 302
[Captures]
deny_id: header "Location" regex "/oauth/consent/([0-9a-f-]{36})$"

POST {{base_url}}/api/idp/requests/{{deny_id}}/decision
Authorization: Bearer {{token}}
Content-Type: application/json
{ "approve": false }

HTTP 200
[Asserts]
jsonpath "$.redirect_to" contains "error=access_denied"
jsonpath "$.redirect_to" contains "state=s-deny"
jsonpath "$.redirect_to" not contains "code="
