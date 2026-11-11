-- OxiCloud as OpenID Provider: the `preferred_username` each relying party
-- was first told for a user, frozen for the lifetime of the deployment.
--
-- Why frozen: a relying party such as a Matrix homeserver mints a permanent
-- identifier (the MXID localpart) from this claim on first login. If the
-- claim followed later profile changes, the same person would surface as a
-- second account. See docs/plan/chat-matrix.md § seam 1.
--
-- Why no foreign key to auth.users and no ON DELETE CASCADE: the row is a
-- tombstone that keeps the handle reserved after the user is deleted.
-- Freeing it would let a NEW user inherit the old handle, and a relying
-- party that matches existing accounts by that claim (Tuwunel with
-- `trusted = true`) would hand them the deleted person's account.
CREATE TABLE auth.idp_subject_bindings (
    client_id          TEXT        NOT NULL,
    user_id            UUID        NOT NULL,
    preferred_username TEXT        NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (client_id, user_id),
    CONSTRAINT idp_subject_bindings_handle_unique UNIQUE (client_id, preferred_username),
    CONSTRAINT idp_subject_bindings_handle_shape
        CHECK (preferred_username ~ '^[a-z0-9._-]{1,64}$')
);

COMMENT ON TABLE auth.idp_subject_bindings IS
    'Per-relying-party preferred_username, frozen at first issuance. Rows outlive the user on purpose (tombstones); see migration header.';
