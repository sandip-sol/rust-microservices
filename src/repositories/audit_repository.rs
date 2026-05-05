use sqlx::PgPool;
use uuid::Uuid;

use crate::models::audit::{AuditLog, NewAuditLog};

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
}
