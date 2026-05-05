use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    models::{audit::AuditLog, user::User},
    services::audit_service::sanitize_metadata,
};

#[derive(Debug, Deserialize)]
pub struct ListUsersQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub role: Option<String>,
    pub email: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListAuditLogsQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub request_id: Option<String>,
    pub user_id: Option<Uuid>,
    pub action: Option<String>,
    pub status: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy)]
pub struct Pagination {
    pub page: i64,
    pub per_page: i64,
    pub offset: i64,
}

#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T>
where
    T: Serialize,
{
    pub items: Vec<T>,
    pub page: i64,
    pub per_page: i64,
    pub total: i64,
}

impl<T> PaginatedResponse<T>
where
    T: Serialize,
{
    pub fn new(items: Vec<T>, pagination: Pagination, total: i64) -> Self {
        Self {
            items,
            page: pagination.page,
            per_page: pagination.per_page,
            total,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AdminUserResponse {
    pub id: Uuid,
    pub email: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

impl From<User> for AdminUserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            role: user.role,
            created_at: user.created_at,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AdminAuditLogResponse {
    pub id: Uuid,
    pub request_id: Option<String>,
    pub user_id: Option<Uuid>,
    pub action: String,
    pub resource: Option<String>,
    pub status: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
}

impl From<AuditLog> for AdminAuditLogResponse {
    fn from(log: AuditLog) -> Self {
        Self {
            id: log.id,
            request_id: log.request_id,
            user_id: log.user_id,
            action: log.action,
            resource: log.resource,
            status: log.status,
            ip_address: log.ip_address,
            user_agent: log.user_agent,
            metadata: sanitize_metadata(log.metadata),
            created_at: log.created_at,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct UpstreamHealthResponse {
    pub status: String,
    pub services: Vec<UpstreamHealth>,
}

#[derive(Debug, Serialize)]
pub struct UpstreamHealth {
    pub name: String,
    pub status: String,
    pub status_code: Option<u16>,
    pub latency_ms: u128,
}

#[derive(Debug, Serialize)]
pub struct RateLimitVisibilityResponse {
    pub enabled: bool,
    pub window_seconds: u64,
    pub policies: Vec<RateLimitPolicyVisibility>,
    pub redis: RateLimitRedisVisibility,
}

#[derive(Debug, Serialize)]
pub struct RateLimitPolicyVisibility {
    pub name: String,
    pub limit: u32,
}

#[derive(Debug, Serialize)]
pub struct RateLimitRedisVisibility {
    pub status: String,
    pub scanned_key_count: usize,
    pub counters: Vec<RateLimitCounterVisibility>,
}

#[derive(Debug, Serialize)]
pub struct RateLimitCounterVisibility {
    pub key: String,
    pub current: Option<u64>,
    pub ttl_seconds: Option<i64>,
}
