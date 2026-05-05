use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::{
    admin::Pagination,
    audit::{AuditLog, NewAuditLog},
};

#[derive(Debug, Clone)]
pub struct AuditLogListFilters {
    pub request_id: Option<String>,
    pub user_id: Option<Uuid>,
    pub action: Option<String>,
    pub status: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
}

#[derive(Clone)]
pub struct AuditRepository {
    pool: PgPool,
}

impl AuditRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, audit_log: NewAuditLog) -> Result<AuditLog, sqlx::Error> {
        sqlx::query_as::<_, AuditLog>(
            r#"
            INSERT INTO audit_logs (
                id,
                request_id,
                user_id,
                action,
                resource,
                status,
                ip_address,
                user_agent,
                metadata,
                created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
            RETURNING
                id,
                request_id,
                user_id,
                action,
                resource,
                status,
                ip_address,
                user_agent,
                metadata,
                created_at
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(audit_log.request_id)
        .bind(audit_log.user_id)
        .bind(audit_log.action)
        .bind(audit_log.resource)
        .bind(audit_log.status)
        .bind(audit_log.ip_address)
        .bind(audit_log.user_agent)
        .bind(audit_log.metadata)
        .fetch_one(&self.pool)
        .await
    }

    pub async fn list_by_request_id(&self, request_id: &str) -> Result<Vec<AuditLog>, sqlx::Error> {
        sqlx::query_as::<_, AuditLog>(
            r#"
            SELECT
                id,
                request_id,
                user_id,
                action,
                resource,
                status,
                ip_address,
                user_agent,
                metadata,
                created_at
            FROM audit_logs
            WHERE request_id = $1
            ORDER BY created_at ASC
            "#,
        )
        .bind(request_id)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<AuditLog>, sqlx::Error> {
        sqlx::query_as::<_, AuditLog>(
            r#"
            SELECT
                id,
                request_id,
                user_id,
                action,
                resource,
                status,
                ip_address,
                user_agent,
                metadata,
                created_at
            FROM audit_logs
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn list(
        &self,
        filters: AuditLogListFilters,
        pagination: Pagination,
    ) -> Result<(Vec<AuditLog>, i64), sqlx::Error> {
        let total = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*)
            FROM audit_logs
            WHERE ($1::TEXT IS NULL OR request_id = $1)
              AND ($2::UUID IS NULL OR user_id = $2)
              AND ($3::TEXT IS NULL OR action = $3)
              AND ($4::TEXT IS NULL OR status = $4)
              AND ($5::TIMESTAMPTZ IS NULL OR created_at >= $5)
              AND ($6::TIMESTAMPTZ IS NULL OR created_at <= $6)
            "#,
        )
        .bind(filters.request_id.as_deref())
        .bind(filters.user_id)
        .bind(filters.action.as_deref())
        .bind(filters.status.as_deref())
        .bind(filters.from)
        .bind(filters.to)
        .fetch_one(&self.pool)
        .await?;

        let logs = sqlx::query_as::<_, AuditLog>(
            r#"
            SELECT
                id,
                request_id,
                user_id,
                action,
                resource,
                status,
                ip_address,
                user_agent,
                metadata,
                created_at
            FROM audit_logs
            WHERE ($1::TEXT IS NULL OR request_id = $1)
              AND ($2::UUID IS NULL OR user_id = $2)
              AND ($3::TEXT IS NULL OR action = $3)
              AND ($4::TEXT IS NULL OR status = $4)
              AND ($5::TIMESTAMPTZ IS NULL OR created_at >= $5)
              AND ($6::TIMESTAMPTZ IS NULL OR created_at <= $6)
            ORDER BY created_at DESC, id DESC
            LIMIT $7 OFFSET $8
            "#,
        )
        .bind(filters.request_id.as_deref())
        .bind(filters.user_id)
        .bind(filters.action.as_deref())
        .bind(filters.status.as_deref())
        .bind(filters.from)
        .bind(filters.to)
        .bind(pagination.per_page)
        .bind(pagination.offset)
        .fetch_all(&self.pool)
        .await?;

        Ok((logs, total))
    }
}
