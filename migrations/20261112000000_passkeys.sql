-- Passkeys (WebAuthn) — docs/plan/passkeys.md, Phase 1.
--
-- One row per registered credential. `passkey` holds the serialized
-- webauthn_rs::Passkey (public key, algorithm, signature counter, backup
-- state); it carries no secret, the private key never leaves the user's
-- authenticator. `credential_id` is what the browser presents at sign-in,
-- hence UNIQUE and the lookup key.
--
-- ON DELETE CASCADE: a passkey is meaningless without its user, and unlike
-- the IdP subject bindings nothing outside OxiCloud keys off it.
CREATE TABLE auth.passkeys (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    credential_id BYTEA       NOT NULL,
    passkey       JSONB       NOT NULL,
    name          TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ,
    CONSTRAINT passkeys_credential_id_unique UNIQUE (credential_id),
    CONSTRAINT passkeys_name_len CHECK (char_length(name) BETWEEN 1 AND 64)
);

CREATE INDEX passkeys_user_id_idx ON auth.passkeys (user_id);

COMMENT ON TABLE auth.passkeys IS
    'WebAuthn credentials for passkey sign-in. Public keys only; see docs/plan/passkeys.md.';

-- Sessions minted by a passkey sign-in.
ALTER TABLE auth.sessions DROP CONSTRAINT sessions_origin_known;
ALTER TABLE auth.sessions
    ADD CONSTRAINT sessions_origin_known
    CHECK (origin IN ('password', 'opaque', 'magic_link', 'oidc', 'device', 'passkey', 'unknown'));

COMMENT ON COLUMN auth.sessions.origin IS
    'How this session was minted: password | opaque | magic_link | oidc | device | passkey | unknown. Set at INSERT time by the login handler; carried over on refresh.';
