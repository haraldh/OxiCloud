# =============================================================
# OxiCloud – chat discovery via /api/config
# =============================================================
# Pins the wire shape the SPA's /chat page gates on. The nav entry
# shows only when `features.chat === true`, and sign-in starts at
# `chat.homeserver_url`. A dropped field reads as `undefined` in the
# FE, which hides chat on a deployment where the operator turned it
# on, with nothing in the logs to say why.
#
# Run:
#   hurl --variables-file tests/api/hurl.vars \
#        --test tests/api/chat_discovery.hurl
# =============================================================

# Chat is off on the baseline test instance (OXICLOUD_ENABLE_CHAT
# unset): the flag is present and false, and the block is present
# with a null URL, so the shape is the same whether chat is on or off.
GET {{base_url}}/api/config

HTTP 200
[Asserts]
jsonpath "$.features.chat" exists
jsonpath "$.features.chat" isBoolean
jsonpath "$.features.chat" == false
jsonpath "$.chat" exists
jsonpath "$.chat.homeserver_url" == null
