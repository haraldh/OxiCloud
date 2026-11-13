//! PostgreSQL adapter for [`PasskeyStorePort`] (`auth.passkeys`).

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::application::ports::auth_ports::UserStoragePort;
use crate::application::ports::passkey_ports::{
    PasskeyStorePort, PasskeyUserPort, PasskeyUserView, StoredPasskey,
};
use crate::common::errors::{DomainError, ErrorKind};
use crate::infrastructure::repositories::pg::UserPgRepository;

pub struct PasskeyPgRepository {
    pool: Arc<PgPool>,
}

impl PasskeyPgRepository {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[derive(FromRow)]
struct Row {
    id: Uuid,
    user_id: Uuid,
    credential_id: Vec<u8>,
    passkey: serde_json::Value,
    name: String,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
}

impl From<Row> for StoredPasskey {
    fn from(r: Row) -> Self {
        Self {
            id: r.id,
            user_id: r.user_id,
            credential_id: r.credential_id,
            passkey: r.passkey,
            name: r.name,
            created_at: r.created_at,
            last_used_at: r.last_used_at,
        }
    }
}

const COLUMNS: &str = "id, user_id, credential_id, passkey, name, created_at, last_used_at";

fn db_err(e: sqlx::Error) -> DomainError {
    DomainError::database_error(format!("passkeys: {e}"))
}

#[async_trait]
impl PasskeyStorePort for PasskeyPgRepository {
    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<StoredPasskey>, DomainError> {
        let rows: Vec<Row> = sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM auth.passkeys WHERE user_id = $1 ORDER BY created_at"
        ))
        .bind(user_id)
        .fetch_all(self.pool.as_ref())
        .await
        .map_err(db_err)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn find_by_credential_id(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<StoredPasskey>, DomainError> {
        let row: Option<Row> = sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM auth.passkeys WHERE credential_id = $1"
        ))
        .bind(credential_id)
        .fetch_optional(self.pool.as_ref())
        .await
        .map_err(db_err)?;
        Ok(row.map(Into::into))
    }

    async fn insert(
        &self,
        user_id: Uuid,
        credential_id: &[u8],
        passkey: &serde_json::Value,
        name: &str,
    ) -> Result<StoredPasskey, DomainError> {
        let row: Option<Row> = sqlx::query_as(&format!(
            "INSERT INTO auth.passkeys (user_id, credential_id, passkey, name)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (credential_id) DO NOTHING
             RETURNING {COLUMNS}"
        ))
        .bind(user_id)
        .bind(credential_id)
        .bind(passkey)
        .bind(name)
        .fetch_optional(self.pool.as_ref())
        .await
        .map_err(db_err)?;
        row.map(Into::into)
            .ok_or_else(|| DomainError::already_exists("Passkey", "credential"))
    }

    async fn record_use(&self, id: Uuid, passkey: &serde_json::Value) -> Result<(), DomainError> {
        sqlx::query("UPDATE auth.passkeys SET passkey = $2, last_used_at = now() WHERE id = $1")
            .bind(id)
            .bind(passkey)
            .execute(self.pool.as_ref())
            .await
            .map_err(db_err)?;
        Ok(())
    }

    async fn rename(&self, user_id: Uuid, id: Uuid, name: &str) -> Result<bool, DomainError> {
        let res = sqlx::query("UPDATE auth.passkeys SET name = $3 WHERE id = $1 AND user_id = $2")
            .bind(id)
            .bind(user_id)
            .bind(name)
            .execute(self.pool.as_ref())
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected() == 1)
    }

    async fn delete(&self, user_id: Uuid, id: Uuid) -> Result<bool, DomainError> {
        let res = sqlx::query("DELETE FROM auth.passkeys WHERE id = $1 AND user_id = $2")
            .bind(id)
            .bind(user_id)
            .execute(self.pool.as_ref())
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected() == 1)
    }
}

/// Exposes [`UserPgRepository`] through the passkey service's narrow port.
pub struct PasskeyUserDirectoryPg {
    users: Arc<UserPgRepository>,
}

impl PasskeyUserDirectoryPg {
    pub fn new(users: Arc<UserPgRepository>) -> Self {
        Self { users }
    }
}

impl PasskeyUserDirectoryPg {
    /// `Ok(None)` only for NotFound: a read failure is never proof of
    /// absence.
    async fn view(
        &self,
        found: Result<crate::domain::entities::user::User, DomainError>,
    ) -> Result<Option<PasskeyUserView>, DomainError> {
        let u = match found {
            Ok(u) => u,
            Err(e) if e.kind == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let opaque = self.users.is_opaque_registered(u.id()).await?;
        Ok(Some(PasskeyUserView {
            id: u.id(),
            account_name: u.username().unwrap_or(u.email()).to_string(),
            display_name: u.display_full(false),
            is_active: u.is_active(),
            is_external: u.is_external(),
            has_other_login: u.has_login_credential() || opaque,
            is_federated: u.federation_subject().is_some(),
            has_password: u.password_hash().is_some() || opaque,
        }))
    }
}

#[async_trait]
impl PasskeyUserPort for PasskeyUserDirectoryPg {
    async fn find_user(&self, id: Uuid) -> Result<Option<PasskeyUserView>, DomainError> {
        self.view(self.users.get_user_by_id(id).await).await
    }

    async fn find_user_by_name(&self, name: &str) -> Result<Option<PasskeyUserView>, DomainError> {
        self.view(self.users.get_user_by_username(name).await).await
    }
}

/// Clears a user's password (legacy hash and OPAQUE envelope with its
/// metadata) — [`PasswordCredentialPort`].
pub struct PasswordCredentialPg {
    pool: Arc<PgPool>,
}

impl PasswordCredentialPg {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl crate::application::ports::passkey_ports::PasswordCredentialPort for PasswordCredentialPg {
    async fn remove_password(&self, user_id: Uuid) -> Result<bool, DomainError> {
        let res = sqlx::query(
            r#"
            UPDATE auth.users
               SET password_hash              = NULL,
                   opaque_envelope            = NULL,
                   opaque_ciphersuite_version = NULL,
                   opaque_registered_at       = NULL,
                   opaque_migrated_at         = NULL,
                   opaque_ksf_memory_kib      = NULL,
                   opaque_ksf_iterations      = NULL,
                   opaque_ksf_parallelism     = NULL,
                   updated_at                 = NOW()
             WHERE id = $1 AND federation_subject IS NULL
            "#,
        )
        .bind(user_id)
        .execute(&*self.pool)
        .await
        .map_err(|e| DomainError::internal_error("PasswordCredential", e.to_string()))?;
        Ok(res.rows_affected() == 1)
    }
}

#[cfg(all(test, integration_tests))]
mod integration_tests {
    use super::*;
    use crate::application::ports::passkey_ports::PasswordCredentialPort;
    use crate::application::ports::recovery_code_ports::RecoveryCodeStorePort;
    use crate::infrastructure::repositories::pg::RecoveryCodePgRepository;
    use crate::integration_test_support::{ensure_clean_test_db, test_db_url};
    use sqlx::postgres::PgPoolOptions;

    async fn pool() -> Arc<PgPool> {
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&test_db_url())
            .await
            .expect("connect to integration-test PostgreSQL");
        ensure_clean_test_db(&pool).await;
        Arc::new(pool)
    }

    /// Hermetic user with a password hash and an OPAQUE envelope; an OIDC
    /// subject when `federated`.
    async fn seed(pool: &PgPool, federated: bool) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO auth.users (
                id, username, email, password_hash, role,
                storage_quota_bytes, storage_used_bytes,
                created_at, updated_at, active,
                opaque_envelope, opaque_ciphersuite_version, opaque_registered_at,
                federation_kind, federation_issuer, federation_subject
            ) VALUES (
                $1, NULL, $2, 'argon2-hash', 'user'::auth.userrole,
                0, 0, NOW(), NOW(), TRUE,
                '\x00'::bytea, 1, NOW(),
                $3, $4, $5
            )
            "#,
        )
        .bind(id)
        .bind(format!("pw-removal-{id}@example.test"))
        .bind(federated.then_some("oidc"))
        .bind(federated.then_some("https://idp.example.test"))
        .bind(federated.then(|| id.to_string()))
        .execute(pool)
        .await
        .expect("seed user");
        id
    }

    async fn credentials(pool: &PgPool, id: Uuid) -> (bool, bool) {
        sqlx::query_as(
            "SELECT password_hash IS NOT NULL, opaque_envelope IS NOT NULL
             FROM auth.users WHERE id = $1",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn removing_the_password_clears_hash_and_envelope() {
        let pool = pool().await;
        let id = seed(&pool, false).await;
        assert!(
            PasswordCredentialPg::new(pool.clone())
                .remove_password(id)
                .await
                .unwrap()
        );
        assert_eq!(credentials(&pool, id).await, (false, false));
    }

    /// The service checks this too; the WHERE clause is the backstop for a
    /// race between the check and the write.
    #[tokio::test]
    async fn a_federated_password_is_left_alone() {
        let pool = pool().await;
        let id = seed(&pool, true).await;
        assert!(
            !PasswordCredentialPg::new(pool.clone())
                .remove_password(id)
                .await
                .unwrap()
        );
        assert_eq!(credentials(&pool, id).await, (true, true));
    }

    /// The magic-link ladder refuses passkey users; this is the lookup it
    /// relies on (fails closed on error, so only the happy paths here).
    #[tokio::test]
    async fn passkey_presence_is_seen_by_the_user_repository() {
        let pool = pool().await;
        let id = seed(&pool, false).await;
        let users = UserPgRepository::new(pool.clone());
        assert!(!users.has_passkeys_or_unknown(id).await);
        PasskeyPgRepository::new(pool.clone())
            .insert(id, id.as_bytes(), &serde_json::json!({}), "Laptop")
            .await
            .unwrap();
        assert!(users.has_passkeys_or_unknown(id).await);
    }

    #[tokio::test]
    async fn recovery_codes_round_trip_in_postgres() {
        let pool = pool().await;
        let id = seed(&pool, false).await;
        let repo = RecoveryCodePgRepository::new(pool.clone());
        let a = [1u8; 32];
        let b = [2u8; 32];
        repo.replace_for_user(id, &[a, b]).await.unwrap();
        let st = repo.status(id).await.unwrap();
        assert_eq!(st.remaining, 2);
        assert!(st.generated_at.is_some());
        assert!(repo.consume(id, &a).await.unwrap());
        assert!(!repo.consume(id, &a).await.unwrap(), "single use");
        assert_eq!(repo.status(id).await.unwrap().remaining, 1);
        // A new set retires the old one in the same transaction.
        repo.replace_for_user(id, &[[3u8; 32]]).await.unwrap();
        assert!(!repo.consume(id, &b).await.unwrap());
        assert_eq!(repo.status(id).await.unwrap().remaining, 1);
    }
}
