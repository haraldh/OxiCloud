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
        let has_other_login =
            u.has_login_credential() || self.users.is_opaque_registered(u.id()).await?;
        Ok(Some(PasskeyUserView {
            id: u.id(),
            account_name: u.username().unwrap_or(u.email()).to_string(),
            display_name: u.display_full(false),
            is_active: u.is_active(),
            is_external: u.is_external(),
            has_other_login,
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
