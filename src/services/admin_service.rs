use std::time::Instant;

use redis::AsyncCommands;
use uuid::Uuid;

use crate::{
    app::state::AppState,
    errors::AppError,
    models::admin::{
        AdminAuditLogResponse, AdminUserResponse, ListAuditLogsQuery, ListUsersQuery,
        PaginatedResponse, Pagination, RateLimitCounterVisibility, RateLimitPolicyVisibility,
        RateLimitRedisVisibility, RateLimitVisibilityResponse, UpstreamHealth,
        UpstreamHealthResponse,
    },
    repositories::{audit_repository::AuditLogListFilters, user_repository::UserListFilters},
    services::rate_limit_service::sanitize_rate_limit_prefix,
};

const DEFAULT_PAGE: u32 = 1;
const DEFAULT_PER_PAGE: u32 = 20;
const MAX_PER_PAGE: u32 = 100;
const MAX_FILTER_LEN: usize = 128;
const RATE_LIMIT_COUNTER_SAMPLE_SIZE: usize = 100;

#[derive(Clone)]
pub struct AdminService {
    app_state: AppState,
}

impl AdminService {
    pub fn new(app_state: AppState) -> Self {
        Self { app_state }
    }

    pub async fn list_users(
        &self,
        query: ListUsersQuery,
    ) -> Result<PaginatedResponse<AdminUserResponse>, AppError> {
        let pagination = pagination(query.page, query.per_page)?;
        let filters = UserListFilters {
            role: validate_role_filter(query.role)?,
            email: validate_optional_filter(query.email, "email")?,
        };

        let (users, total) = self
            .app_state
            .user_repository
            .list(filters, pagination)
            .await
            .map_err(|_| AppError::Database)?;
        let users = users.into_iter().map(AdminUserResponse::from).collect();

        Ok(PaginatedResponse::new(users, pagination, total))
    }

    pub async fn get_user(&self, user_id: Uuid) -> Result<AdminUserResponse, AppError> {
        let user = self
            .app_state
            .user_repository
            .find_by_id(user_id)
            .await
            .map_err(|_| AppError::Database)?
            .ok_or_else(|| AppError::NotFound("user not found".to_string()))?;

        Ok(AdminUserResponse::from(user))
    }

    pub async fn list_audit_logs(
        &self,
        query: ListAuditLogsQuery,
    ) -> Result<PaginatedResponse<AdminAuditLogResponse>, AppError> {
        let pagination = pagination(query.page, query.per_page)?;
        let filters = AuditLogListFilters {
            request_id: validate_optional_filter(query.request_id, "request_id")?,
            user_id: query.user_id,
            action: validate_optional_filter(query.action, "action")?,
            status: validate_status_filter(query.status)?,
            from: query.from,
            to: query.to,
        };

        if let (Some(from), Some(to)) = (filters.from, filters.to) {
            if from > to {
                return Err(AppError::BadRequest(
                    "from must be earlier than or equal to to".to_string(),
                ));
            }
        }

        let (logs, total) = self
            .app_state
            .audit_repository
            .list(filters, pagination)
            .await
            .map_err(|_| AppError::Database)?;
        let logs = logs.into_iter().map(AdminAuditLogResponse::from).collect();

        Ok(PaginatedResponse::new(logs, pagination, total))
    }

    pub async fn get_audit_log(
        &self,
        audit_log_id: Uuid,
    ) -> Result<AdminAuditLogResponse, AppError> {
        let log = self
            .app_state
            .audit_repository
            .find_by_id(audit_log_id)
            .await
            .map_err(|_| AppError::Database)?
            .ok_or_else(|| AppError::NotFound("audit log not found".to_string()))?;

        Ok(AdminAuditLogResponse::from(log))
    }

    pub async fn upstream_health(&self) -> UpstreamHealthResponse {
        let services = vec![
            self.check_upstream("user", &self.app_state.settings.user_service_url)
                .await,
            self.check_upstream("payment", &self.app_state.settings.payment_service_url)
                .await,
        ];
        let status = if services.iter().all(|service| service.status == "up") {
            "ok"
        } else {
            "degraded"
        };

        UpstreamHealthResponse {
            status: status.to_string(),
            services,
        }
    }

    pub async fn rate_limit_visibility(&self) -> RateLimitVisibilityResponse {
        let redis = if self.app_state.settings.rate_limit_enabled {
            self.rate_limit_redis_visibility().await
        } else {
            RateLimitRedisVisibility {
                status: "disabled".to_string(),
                scanned_key_count: 0,
                counters: Vec::new(),
            }
        };

        RateLimitVisibilityResponse {
            enabled: self.app_state.settings.rate_limit_enabled,
            window_seconds: self.app_state.settings.rate_limit_window_seconds,
            policies: vec![
                RateLimitPolicyVisibility {
                    name: "anonymous".to_string(),
                    limit: self.app_state.settings.rate_limit_anon_per_minute,
                },
                RateLimitPolicyVisibility {
                    name: "authenticated".to_string(),
                    limit: self.app_state.settings.rate_limit_auth_per_minute,
                },
                RateLimitPolicyVisibility {
                    name: "auth_endpoint".to_string(),
                    limit: self.app_state.settings.rate_limit_auth_endpoint_per_minute,
                },
            ],
            redis,
        }
    }

    async fn check_upstream(&self, name: &str, base_url: &str) -> UpstreamHealth {
        let started = Instant::now();
        let health_url = format!("{}/health", base_url.trim_end_matches('/'));
        let result = self
            .app_state
            .proxy_http_client
            .get(health_url)
            .send()
            .await;
        let latency_ms = started.elapsed().as_millis();

        match result {
            Ok(response) => {
                let status_code = response.status().as_u16();
                let status = if response.status().is_success() {
                    "up"
                } else {
                    "down"
                };

                UpstreamHealth {
                    name: name.to_string(),
                    status: status.to_string(),
                    status_code: Some(status_code),
                    latency_ms,
                }
            }
            Err(_) => UpstreamHealth {
                name: name.to_string(),
                status: "down".to_string(),
                status_code: None,
                latency_ms,
            },
        }
    }

    async fn rate_limit_redis_visibility(&self) -> RateLimitRedisVisibility {
        let mut connection = match self
            .app_state
            .redis_client
            .get_multiplexed_async_connection()
            .await
        {
            Ok(connection) => connection,
            Err(_) => {
                return RateLimitRedisVisibility {
                    status: "down".to_string(),
                    scanned_key_count: 0,
                    counters: Vec::new(),
                };
            }
        };

        let prefix = sanitize_rate_limit_prefix(&self.app_state.settings.rate_limit_redis_prefix);
        let pattern = format!("{prefix}:*");
        let scanned: Result<(u64, Vec<String>), _> = redis::cmd("SCAN")
            .arg(0_u64)
            .arg("MATCH")
            .arg(pattern)
            .arg("COUNT")
            .arg(RATE_LIMIT_COUNTER_SAMPLE_SIZE)
            .query_async(&mut connection)
            .await;

        let (_, keys) = match scanned {
            Ok(result) => result,
            Err(_) => {
                return RateLimitRedisVisibility {
                    status: "down".to_string(),
                    scanned_key_count: 0,
                    counters: Vec::new(),
                };
            }
        };

        let mut counters = Vec::new();
        for key in keys.iter().take(RATE_LIMIT_COUNTER_SAMPLE_SIZE) {
            let current = connection.get::<_, Option<u64>>(key).await.ok().flatten();
            let ttl_seconds = connection.ttl::<_, i64>(key).await.ok();
            counters.push(RateLimitCounterVisibility {
                key: key.clone(),
                current,
                ttl_seconds,
            });
        }

        RateLimitRedisVisibility {
            status: "up".to_string(),
            scanned_key_count: keys.len(),
            counters,
        }
    }
}

fn pagination(page: Option<u32>, per_page: Option<u32>) -> Result<Pagination, AppError> {
    let page = page.unwrap_or(DEFAULT_PAGE);
    let per_page = per_page.unwrap_or(DEFAULT_PER_PAGE);

    if page == 0 {
        return Err(AppError::BadRequest(
            "page must be greater than 0".to_string(),
        ));
    }

    if per_page == 0 || per_page > MAX_PER_PAGE {
        return Err(AppError::BadRequest(format!(
            "per_page must be between 1 and {MAX_PER_PAGE}"
        )));
    }

    let page = i64::from(page);
    let per_page = i64::from(per_page);
    Ok(Pagination {
        page,
        per_page,
        offset: (page - 1) * per_page,
    })
}

fn validate_role_filter(role: Option<String>) -> Result<Option<String>, AppError> {
    let Some(role) = validate_optional_filter(role, "role")? else {
        return Ok(None);
    };

    match role.as_str() {
        "user" | "admin" | "service" => Ok(Some(role)),
        _ => Err(AppError::BadRequest("unsupported role filter".to_string())),
    }
}

fn validate_status_filter(status: Option<String>) -> Result<Option<String>, AppError> {
    let Some(status) = validate_optional_filter(status, "status")? else {
        return Ok(None);
    };

    match status.as_str() {
        "success" | "failure" | "denied" => Ok(Some(status)),
        _ => Err(AppError::BadRequest(
            "unsupported status filter".to_string(),
        )),
    }
}

fn validate_optional_filter(
    value: Option<String>,
    field_name: &'static str,
) -> Result<Option<String>, AppError> {
    let Some(value) = value else {
        return Ok(None);
    };

    let value = value.trim().to_string();
    if value.is_empty() {
        return Ok(None);
    }

    if value.chars().count() > MAX_FILTER_LEN {
        return Err(AppError::BadRequest(format!(
            "{field_name} filter is too long"
        )));
    }

    Ok(Some(value))
}
