-- Recovery codes (docs/plan/passkeys.md, Phase 2a step 3): ten single-use
-- codes a user keeps somewhere safe, for when every passkey is gone.
--
-- Stored as SHA-256, not Argon2: each code carries 80 random bits, so a
-- slow hash adds nothing, and a sign-in attempt costs one indexed lookup
-- instead of ten Argon2 runs.
CREATE TABLE auth.recovery_codes (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    code_hash  BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    used_at    TIMESTAMPTZ,
    CONSTRAINT recovery_codes_hash_len CHECK (octet_length(code_hash) = 32),
    CONSTRAINT recovery_codes_user_hash UNIQUE (user_id, code_hash)
);
CREATE INDEX recovery_codes_user_id ON auth.recovery_codes(user_id);

-- Sessions minted by a recovery code.
ALTER TABLE auth.sessions DROP CONSTRAINT sessions_origin_known;
ALTER TABLE auth.sessions
    ADD CONSTRAINT sessions_origin_known
    CHECK (origin IN ('password', 'opaque', 'magic_link', 'oidc', 'device', 'passkey', 'recovery', 'unknown'));
