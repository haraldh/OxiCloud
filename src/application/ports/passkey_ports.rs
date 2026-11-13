//! Storage port for passkeys (WebAuthn credentials).
//!
//! See `application/services/passkey_service.rs` and
//! `docs/plan/passkeys.md`.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::common::errors::DomainError;

/// One stored credential. `passkey` is the serialized
/// `webauthn_rs::prelude::Passkey`; the store treats it as opaque JSON so
/// the port stays free of the WebAuthn library's types.
#[derive(Debug, Clone)]
pub struct StoredPasskey {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub passkey: serde_json::Value,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[async_trait]
pub trait PasskeyStorePort: Send + Sync + 'static {
    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<StoredPasskey>, DomainError>;

    /// `Ok(None)` only when no row has this credential id.
    async fn find_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<StoredPasskey>, DomainError>;

    /// Fails with `AlreadyExists` when the credential id is already
    /// registered (to this or any other user).
    async fn insert(
        &self,
        user_id: Uuid,
        credential_id: &[u8],
        passkey: &serde_json::Value,
        name: &str,
    ) -> Result<StoredPasskey, DomainError>;

    /// After a sign-in: store the updated credential (signature counter,
    /// backup state) and stamp `last_used_at`.
    async fn record_use(&self, id: Uuid, passkey: &serde_json::Value) -> Result<(), DomainError>;

    /// `Ok(false)` when the row does not exist or belongs to someone else.
    async fn rename(&self, user_id: Uuid, id: Uuid, name: &str) -> Result<bool, DomainError>;

    /// `Ok(false)` when the row does not exist or belongs to someone else.
    async fn delete(&self, user_id: Uuid, id: Uuid) -> Result<bool, DomainError>;
}

/// The slice of a user the passkey service needs.
#[derive(Debug, Clone)]
pub struct PasskeyUserView {
    pub id: Uuid,
    /// Shown by the authenticator when picking an account.
    pub account_name: String,
    pub display_name: String,
    pub is_active: bool,
    pub is_external: bool,
    /// The user can sign in some other way: a password (legacy hash or
    /// OPAQUE envelope) or a linked OIDC identity. Magic links don't
    /// count, since an operator may switch them off.
    pub has_other_login: bool,
}

#[async_trait]
pub trait PasskeyUserPort: Send + Sync + 'static {
    /// `Ok(None)` only when the user does not exist.
    async fn find_user(&self, id: Uuid) -> Result<Option<PasskeyUserView>, DomainError>;
    /// By sign-in name, as the password login looks users up. `Ok(None)`
    /// only when no such user exists. Used by recovery-code sign-in.
    async fn find_user_by_name(&self, name: &str) -> Result<Option<PasskeyUserView>, DomainError>;
}
