//! Ports for OxiCloud acting as an OpenID Provider.
//!
//! See `application/services/idp_service.rs` for the flow and
//! `docs/plan/chat-matrix.md` § seam 1 for why it exists.

use async_trait::async_trait;
use uuid::Uuid;

use crate::common::errors::DomainError;

/// The slice of a user the provider needs: eligibility plus claims.
#[derive(Debug, Clone)]
pub struct IdpUserView {
    pub id: Uuid,
    pub email: String,
    pub email_verified: bool,
    pub username: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub is_active: bool,
    pub is_external: bool,
}

#[async_trait]
pub trait IdpUserDirectoryPort: Send + Sync + 'static {
    /// `Ok(None)` when the user does not exist (deleted between approval
    /// and token exchange is the realistic case).
    async fn find_user(&self, id: Uuid) -> Result<Option<IdpUserView>, DomainError>;
}

/// Result of trying to reserve a handle for a `(client, user)` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindOutcome {
    /// The pair is bound to this handle — either just now, or by a
    /// concurrent request that won the race.
    Bound(String),
    /// Another user of the same client already holds the handle.
    HandleTaken,
}

#[async_trait]
pub trait IdpSubjectBindingPort: Send + Sync + 'static {
    async fn get_binding(
        &self,
        client_id: &str,
        user_id: Uuid,
    ) -> Result<Option<String>, DomainError>;

    /// Insert-if-absent. Must be race-safe: two concurrent first logins
    /// of the same user resolve to one handle, and two users racing for
    /// the same handle get one `Bound` and one `HandleTaken`.
    async fn try_bind(
        &self,
        client_id: &str,
        user_id: Uuid,
        handle: &str,
    ) -> Result<BindOutcome, DomainError>;
}

/// Signs ID tokens and publishes the matching JWKS.
pub trait IdpTokenSignerPort: Send + Sync + 'static {
    fn sign(&self, claims: &serde_json::Value) -> Result<String, DomainError>;
    fn jwks(&self) -> serde_json::Value;
    /// JOSE `alg` value advertised in discovery.
    fn algorithm(&self) -> &'static str;
}
