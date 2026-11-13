-- Passkeys Phase 2a (docs/plan/passkeys.md, "Phase 2a plan").

-- When the user last proved who they are in this session family: set when a
-- session is minted, carried over on refresh rotation, moved forward by a
-- step-up re-authentication. Sensitive actions (adding or removing a
-- passkey, recovery codes, removing the password) require it to be recent.
-- NULL on rows that predate the column: treated as stale, so the user is
-- asked to confirm once.
ALTER TABLE auth.sessions ADD COLUMN authenticated_at TIMESTAMPTZ;

COMMENT ON COLUMN auth.sessions.authenticated_at IS
    'Last successful authentication (login or step-up) for this session family; NULL = unknown, treated as stale.';
