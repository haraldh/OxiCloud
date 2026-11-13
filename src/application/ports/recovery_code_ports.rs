//! Storage for single-use recovery codes — `docs/plan/passkeys.md`,
//! Phase 2a. Codes are stored hashed (SHA-256 of the normalised code).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::common::errors::DomainError;

/// How many unused codes a user has, and when the set was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryCodeStatus {
    pub remaining: u32,
    pub generated_at: Option<DateTime<Utc>>,
}

#[async_trait]
pub trait RecoveryCodeStorePort: Send + Sync + 'static {
    /// Replace the user's whole set atomically: the old codes stop working
    /// in the same transaction the new ones are written.
    async fn replace_for_user(&self, user_id: Uuid, hashes: &[[u8; 32]])
    -> Result<(), DomainError>;

    async fn status(&self, user_id: Uuid) -> Result<RecoveryCodeStatus, DomainError>;

    /// Mark one unused code of the user as used. `false` when it is not
    /// one of theirs or was already used; a concurrent second use of the
    /// same code loses the race here.
    async fn consume(&self, user_id: Uuid, hash: &[u8; 32]) -> Result<bool, DomainError>;
}
