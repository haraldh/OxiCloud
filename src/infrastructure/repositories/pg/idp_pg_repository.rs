//! PostgreSQL adapters for the OpenID Provider ports.

use std::sync::Arc;

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use crate::application::ports::auth_ports::UserStoragePort;
use crate::application::ports::idp_ports::{
    BindOutcome, IdpSubjectBindingPort, IdpUserDirectoryPort, IdpUserView,
};
use crate::common::errors::{DomainError, ErrorKind};
use crate::infrastructure::repositories::pg::UserPgRepository;

pub struct IdpSubjectBindingPgRepository {
    pool: Arc<PgPool>,
}

impl IdpSubjectBindingPgRepository {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

fn db_err(e: sqlx::Error) -> DomainError {
    DomainError::database_error(format!("idp_subject_bindings: {e}"))
}

#[async_trait]
impl IdpSubjectBindingPort for IdpSubjectBindingPgRepository {
    async fn get_binding(
        &self,
        client_id: &str,
        user_id: Uuid,
    ) -> Result<Option<String>, DomainError> {
        sqlx::query_scalar(
            "SELECT preferred_username FROM auth.idp_subject_bindings
              WHERE client_id = $1 AND user_id = $2",
        )
        .bind(client_id)
        .bind(user_id)
        .fetch_optional(self.pool.as_ref())
        .await
        .map_err(db_err)
    }

    async fn try_bind(
        &self,
        client_id: &str,
        user_id: Uuid,
        handle: &str,
    ) -> Result<BindOutcome, DomainError> {
        // ON CONFLICT DO NOTHING covers both constraints (the pair's PK and
        // the per-client handle UNIQUE) without aborting anything.
        let inserted: Option<String> = sqlx::query_scalar(
            "INSERT INTO auth.idp_subject_bindings (client_id, user_id, preferred_username)
             VALUES ($1, $2, $3)
             ON CONFLICT DO NOTHING
             RETURNING preferred_username",
        )
        .bind(client_id)
        .bind(user_id)
        .bind(handle)
        .fetch_optional(self.pool.as_ref())
        .await
        .map_err(db_err)?;
        if let Some(h) = inserted {
            return Ok(BindOutcome::Bound(h));
        }
        // Either a concurrent first login bound this pair (return that), or
        // another user holds the handle.
        Ok(match self.get_binding(client_id, user_id).await? {
            Some(h) => BindOutcome::Bound(h),
            None => BindOutcome::HandleTaken,
        })
    }
}

/// Exposes [`UserPgRepository`] through the provider's narrow user port.
pub struct IdpUserDirectoryPg {
    users: Arc<UserPgRepository>,
}

impl IdpUserDirectoryPg {
    pub fn new(users: Arc<UserPgRepository>) -> Self {
        Self { users }
    }
}

#[async_trait]
impl IdpUserDirectoryPort for IdpUserDirectoryPg {
    async fn find_user(&self, id: Uuid) -> Result<Option<IdpUserView>, DomainError> {
        match self.users.get_user_by_id(id).await {
            Ok(u) => Ok(Some(IdpUserView {
                id: u.id(),
                email: u.email().to_string(),
                email_verified: u.is_email_verified(),
                username: u.username().map(str::to_string),
                given_name: u.given_name().map(str::to_string),
                family_name: u.family_name().map(str::to_string),
                is_active: u.is_active(),
                is_external: u.is_external(),
            })),
            // A read failure is never proof of absence; only NotFound is.
            Err(e) if e.kind == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(all(test, integration_tests))]
mod integration_tests {
    use super::*;

    async fn pool() -> Arc<PgPool> {
        let url = crate::integration_test_support::test_db_url();
        Arc::new(
            PgPool::connect(&url)
                .await
                .expect("connect to test DB — run tests/common/spawn-db.sh first"),
        )
    }

    /// Pins the two race outcomes the service relies on: re-binding the
    /// same pair returns the original handle, and a second user asking for
    /// a held handle gets `HandleTaken` instead of an error.
    #[tokio::test]
    async fn bind_is_idempotent_and_handles_are_unique_per_client() {
        let repo = IdpSubjectBindingPgRepository::new(pool().await);
        // Unique per run: the shared test DB keeps rows between runs and
        // bindings are tombstones by design.
        let client = format!("it-{}", Uuid::new_v4());
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());

        assert_eq!(
            repo.try_bind(&client, a, "alice").await.unwrap(),
            BindOutcome::Bound("alice".into())
        );
        assert_eq!(
            repo.try_bind(&client, a, "alice-other").await.unwrap(),
            BindOutcome::Bound("alice".into())
        );
        assert_eq!(
            repo.try_bind(&client, b, "alice").await.unwrap(),
            BindOutcome::HandleTaken
        );
        assert_eq!(repo.get_binding(&client, b).await.unwrap(), None);

        // Same handle under another client is independent.
        let other = format!("{client}-2");
        assert_eq!(
            repo.try_bind(&other, b, "alice").await.unwrap(),
            BindOutcome::Bound("alice".into())
        );
    }
}
