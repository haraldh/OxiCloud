#!/usr/bin/env bash
# Generates .env and generated/* for the phase-0 Matrix bench.
#
#   ./init.sh <public-hostname> <acme-email>
#
# Re-running regenerates every secret and password; `docker compose down -v`
# afterwards, or Tuwunel and Dex disagree about the client secret.
set -euo pipefail

cd "$(dirname "$0")"

domain=${1:?usage: ./init.sh <public-hostname> <acme-email>}
email=${2:?usage: ./init.sh <public-hostname> <acme-email>}

caddy_image=$(sed -n 's/^ *image: \(caddy:.*\)$/\1/p' compose.yaml)

rand() { openssl rand -hex "$1"; }
bcrypt() { docker run --rm "$caddy_image" caddy hash-password --plaintext "$1"; }

livekit_key=$(rand 10)
livekit_secret=$(rand 32)
dex_client_secret=$(rand 32)
alice_pw=$(rand 8)
bob_pw=$(rand 8)
carol_pw=$(rand 8)

mkdir -p generated
umask 077

cat > .env <<EOF
BENCH_DOMAIN=$domain
ACME_EMAIL=$email
LIVEKIT_KEY=$livekit_key
LIVEKIT_SECRET=$livekit_secret
EOF

printf '%s' "$dex_client_secret" > generated/dex-client-secret

cat > generated/tuwunel.toml <<EOF
[global]
server_name = "$domain"
database_path = "/var/lib/tuwunel"
address = ["0.0.0.0"]
port = 8008

# Closed island by default (plan § Federation). The OpenID userinfo route
# that lk-jwt-service needs is registered regardless of this flag.
allow_federation = false

# Accounts come only from the upstream IdP.
allow_registration = false

# Built-in OAuth server for Element X, brokering to the upstream IdP only.
oidc_native_auth = false

[global.well_known]
client = "https://$domain"
# Served even with federation off; lk-jwt-service resolves the homeserver
# through it when validating OpenID tokens.
server = "$domain:443"
livekit_url = "https://$domain/livekit/jwt"

[[global.identity_provider]]
brand = "oxicloud"
name = "OxiCloud (Dex stand-in)"
client_id = "tuwunel"
client_secret_file = "/etc/tuwunel/.client_secret"
issuer_url = "https://$domain/dex"
# Phase 1 replaces Dex with OxiCloud, which will send the immutable
# localpart as preferred_username and the user UUID as sub.
userid_claims = ["preferred_username", "email"]
trusted = true
unique_id_fallbacks = false
EOF

user_block() { # name password userid
	cat <<EOF
  - email: "$1@$domain"
    username: "$1"
    preferredUsername: "$1"
    userID: "$3"
    hash: "$(bcrypt "$2")"
EOF
}

cat > generated/dex.yaml <<EOF
issuer: https://$domain/dex
storage:
  type: memory
web:
  http: 0.0.0.0:5556
oauth2:
  skipApprovalScreen: true
enablePasswordDB: true
staticClients:
  - id: tuwunel
    name: Tuwunel
    secret: "$dex_client_secret"
    redirectURIs:
      - "https://$domain/_matrix/client/unstable/login/sso/callback/tuwunel"
staticPasswords:
$(user_block alice "$alice_pw" 0b0e8f4e-0000-4000-8000-00000000a11c)
$(user_block bob "$bob_pw" 0b0e8f4e-0000-4000-8000-000000000b0b)
$(user_block carol "$carol_pw" 0b0e8f4e-0000-4000-8000-0000000ca201)
EOF

cat > generated/livekit.yaml <<EOF
port: 7880
bind_addresses: [""]
rtc:
  tcp_port: 7881
  port_range_start: 50100
  port_range_end: 50200
  # Discovers the public IP via STUN. On a VPS whose public IP is bound to
  # an interface, set use_external_ip: false and node_ip instead.
  use_external_ip: true
  external_ip_only: true
  enable_loopback_candidate: false
turn:
  # Embedded TURN is off on the bench. Turn it on (it needs its own TLS
  # port or UDP port) only if calls from restrictive networks fail.
  enabled: false
keys:
  $livekit_key: $livekit_secret
EOF

cat <<EOF
Bench configured for https://$domain

Login with the email address at the Dex page:
  alice@$domain  $alice_pw
  bob@$domain    $bob_pw
  carol@$domain  $carol_pw

Next: docker compose up -d   (then follow README.md checklist)
EOF
