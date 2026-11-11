# Matrix bench (phase 0 of `docs/plan/chat-matrix.md`)

A throwaway stack to check Tuwunel against real Element X clients before
OxiCloud integrates with it. It is **not** a deployment template. Dex stands
in for the OIDC provider OxiCloud will become in phase 1, and
`lk-jwt-service` (AGPL) stands in for the token endpoint OxiCloud will serve
in phase 2.

## Requirements

- A host reachable from the internet with a DNS name (`A`/`AAAA`) pointing
  at it. Phones need a publicly trusted certificate, so Caddy has to get one
  from Let's Encrypt.
- Open ports: 80/tcp and 443/tcp+udp (Caddy), 7881/tcp and
  50100–50200/udp (LiveKit media).
- Docker with Compose v2, and `openssl`.

## Run

```bash
./init.sh matrix.example.org you@example.org   # prints the test logins
docker compose up -d
docker compose logs -f tuwunel                  # watch the first start
```

Sanity checks before picking up a phone:

```bash
d=matrix.example.org
curl -s https://$d/.well-known/matrix/client          # base_url + rtc_foci
curl -s https://$d/_matrix/client/v1/auth_metadata    # Tuwunel OAuth server
curl -s https://$d/dex/.well-known/openid-configuration
curl -s https://$d/_matrix/client/unstable/org.matrix.msc4143/rtc/transports  # needs a token
curl -s -o /dev/null -w '%{http_code}\n' https://$d/_synapse/mas/query_user   # must be 404
```

Tear down with `docker compose down -v`. Re-running `init.sh` rotates every
secret, so always do `down -v` after it.

## Checklist

Record the result, the client version and the Tuwunel version for each item
in the plan's phase-0 notes. Use two devices: an iPhone and an Android
phone.

| # | Check | Pass |
|---|---|---|
| 1 | Element X login: enter the hostname → Dex page → back in the app as `@alice:<domain>` | |
| 2 | Second login as `bob` on the other phone | |
| 3 | E2EE DM alice ↔ bob, both directions, after killing and restarting both apps | |
| 4 | Background push: lock bob's phone, alice sends; notification arrives within ~10 s (iOS and Android) | |
| 5 | Private group room with `carol` on Element Web or a third device | |
| 6 | 1:1 call alice ↔ bob, audio and video, one phone on mobile data | |
| 7 | Group call with 3–4 participants | |
| 8 | QR login: sign in Element X on a third device by scanning from a signed-in one | |
| 9 | "Manage account" in Element X lands on the right page (Tuwunel #639) | |
| 10 | Log out all devices for bob through `/_synapse/mas/sync_devices` with an empty device list (from inside the compose network); bob's apps drop to the login screen | |
| 11 | `docker compose restart tuwunel` during an active DM; nothing is lost | |
| 12 | Online backup (`!admin server backup-database` in the admin room with `database.backup.path` set), then restore it into a fresh volume | |

Then repeat 1–7 with Continuwuity instead of Tuwunel (swap the image and
translate the config) before choosing the homeserver.
