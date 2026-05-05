use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::refresh_token::RefreshToken;

#[derive(Clone)]
pub struct RefreshTokenRepository {
    pool: PgPool,
}

impl RefreshTokenRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        user_id: Uuid,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<RefreshToken, sqlx::Error> {
        let token_id = Uuid::new_v4();

        sqlx::query_as::<_, RefreshToken>(
            r#"
            INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at)
            VALUES ($1, $2, $3, $4)
            RETURNING id, user_id, token_hash, expires_at, revoked_at, created_at
            "#,
        )
        .bind(token_id)
        .bind(user_id)
        .bind(token_hash)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn find_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<RefreshToken>, sqlx::Error> {
        sqlx::query_as::<_, RefreshToken>(
            r#"
            SELECT id, user_id, token_hash, expires_at, revoked_at, created_at
            FROM refresh_tokens
            WHERE token_hash = $1
            "#,
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn revoke(&self, token_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE refresh_tokens
            SET revoked_at = COALESCE(revoked_at, NOW())
            WHERE id = $1
            "#,
        )
        .bind(token_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn revoke_by_hash(&self, token_hash: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE refresh_tokens
            SET revoked_at = COALESCE(revoked_at, NOW())
            WHERE token_hash = $1
            "#,
        )
        .bind(token_hash)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn revoke_all_for_user(&self, user_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE refresh_tokens
            SET revoked_at = COALESCE(revoked_at, NOW())
            WHERE user_id = $1
              AND revoked_at IS NULL
            "#,
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn rotate(
        &self,
        old_token_id: Uuid,
        user_id: Uuid,
        new_token_hash: &str,
        new_expires_at: DateTime<Utc>,
    ) -> Result<Option<RefreshToken>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;

        let revoke_result = sqlx::query(
            r#"
            UPDATE refresh_tokens
            SET revoked_at = NOW()
            WHERE id = $1
              AND user_id = $2
              AND revoked_at IS NULL
              AND expires_at > NOW()
            "#,
        )
        .bind(old_token_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        if revoke_result.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(None);
        }

        let new_token = sqlx::query_as::<_, RefreshToken>(
            r#"
            INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at)
            VALUES ($1, $2, $3, $4)
            RETURNING id, user_id, token_hash, expires_at, revoked_at, created_at
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(new_token_hash)
        .bind(new_expires_at)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(Some(new_token))
    }
}
