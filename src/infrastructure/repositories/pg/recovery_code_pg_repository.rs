//! PostgreSQL adapter for [`RecoveryCodeStorePort`] (`auth.recovery_codes`).

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::application::ports::recovery_code_ports::{RecoveryCodeStatus, RecoveryCodeStorePort};
use crate::common::errors::DomainError;

pub struct RecoveryCodePgRepository {
    pool: Arc<PgPool>,
}

impl RecoveryCodePgRepository {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

fn db(e: sqlx::Error) -> DomainError {
    DomainError::internal_error("RecoveryCodes", e.to_string())
}

#[async_trait]
impl RecoveryCodeStorePort for RecoveryCodePgRepository {
    async fn replace_for_user(
        &self,
        user_id: Uuid,
        hashes: &[[u8; 32]],
    ) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query("DELETE FROM auth.recovery_codes WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        let rows: Vec<Vec<u8>> = hashes.iter().map(|h| h.to_vec()).collect();
        sqlx::query(
            "INSERT INTO auth.recovery_codes (user_id, code_hash)
             SELECT $1, h FROM UNNEST($2::bytea[]) AS h",
        )
        .bind(user_id)
        .bind(&rows)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        tx.commit().await.map_err(db)
    }

    async fn status(&self, user_id: Uuid) -> Result<RecoveryCodeStatus, DomainError> {
        let (remaining, generated_at): (i64, Option<DateTime<Utc>>) = sqlx::query_as(
            "SELECT count(*) FILTER (WHERE used_at IS NULL), min(created_at)
             FROM auth.recovery_codes WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_one(&*self.pool)
        .await
        .map_err(db)?;
        Ok(RecoveryCodeStatus {
            remaining: u32::try_from(remaining).unwrap_or(u32::MAX),
            generated_at,
        })
    }

    async fn consume(&self, user_id: Uuid, hash: &[u8; 32]) -> Result<bool, DomainError> {
        let res = sqlx::query(
            "UPDATE auth.recovery_codes SET used_at = now()
             WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL",
        )
        .bind(user_id)
        .bind(&hash[..])
        .execute(&*self.pool)
        .await
        .map_err(db)?;
        Ok(res.rows_affected() == 1)
    }
}
