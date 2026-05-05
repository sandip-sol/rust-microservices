use sqlx::PgPool;
use uuid::Uuid;

use crate::models::{admin::Pagination, user::User};

#[derive(Debug, Clone)]
pub struct UserListFilters {
    pub role: Option<String>,
    pub email: Option<String>,
}

#[derive(Clone)]
pub struct UserRepository {
    pool: PgPool,
}

impl UserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn find_by_email(&self, email: &str) -> Result<Option<User>, sqlx::Error> {
        sqlx::query_as::<_, User>(
            r#"
            SELECT id, email, password_hash, role, created_at
            FROM users
            WHERE email = $1
            "#,
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn find_by_id(&self, user_id: Uuid) -> Result<Option<User>, sqlx::Error> {
        sqlx::query_as::<_, User>(
            r#"
            SELECT id, email, password_hash, role, created_at
            FROM users
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn list(
        &self,
        filters: UserListFilters,
        pagination: Pagination,
    ) -> Result<(Vec<User>, i64), sqlx::Error> {
        let email_pattern = filters
            .email
            .as_ref()
            .map(|email| format!("%{}%", email.replace(['%', '_'], "")));

        let total = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*)
            FROM users
            WHERE ($1::TEXT IS NULL OR role = $1)
              AND ($2::TEXT IS NULL OR email ILIKE $2)
            "#,
        )
        .bind(filters.role.as_deref())
        .bind(email_pattern.as_deref())
        .fetch_one(&self.pool)
        .await?;

        let users = sqlx::query_as::<_, User>(
            r#"
            SELECT id, email, password_hash, role, created_at
            FROM users
            WHERE ($1::TEXT IS NULL OR role = $1)
              AND ($2::TEXT IS NULL OR email ILIKE $2)
            ORDER BY created_at DESC, id DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(filters.role.as_deref())
        .bind(email_pattern.as_deref())
        .bind(pagination.per_page)
        .bind(pagination.offset)
        .fetch_all(&self.pool)
        .await?;

        Ok((users, total))
    }

    pub async fn create_user(
        &self,
        email: &str,
        password_hash: &str,
        role: &str,
    ) -> Result<User, sqlx::Error> {
        let user_id = Uuid::new_v4();

        sqlx::query_as::<_, User>(
            r#"
            INSERT INTO users (id, email, password_hash, role, created_at)
            VALUES ($1, $2, $3, $4, NOW())
            RETURNING id, email, password_hash, role, created_at
            "#,
        )
        .bind(user_id)
        .bind(email)
        .bind(password_hash)
        .bind(role)
        .fetch_one(&self.pool)
        .await
    }
}
