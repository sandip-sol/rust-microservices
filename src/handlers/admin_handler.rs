use actix_web::{HttpRequest, HttpResponse, web};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    app::state::AppState,
    errors::AppError,
    middleware::auth::RequireAdmin,
    models::{
        admin::{ListAuditLogsQuery, ListUsersQuery},
        audit::AuditStatus,
    },
    services::{admin_service::AdminService, audit_service::AuditEvent},
};

const ACTION_ADMIN_USERS_LIST: &str = "admin.users.list";
const ACTION_ADMIN_USERS_DETAIL: &str = "admin.users.detail";
const ACTION_ADMIN_AUDIT_LOGS_LIST: &str = "admin.audit_logs.list";
const ACTION_ADMIN_AUDIT_LOGS_DETAIL: &str = "admin.audit_logs.detail";
const ACTION_ADMIN_UPSTREAM_HEALTH: &str = "admin.upstreams.health";
const ACTION_ADMIN_RATE_LIMITS_VIEW: &str = "admin.rate_limits.view";

pub async fn list_users(
    request: HttpRequest,
    app_state: web::Data<AppState>,
    admin: RequireAdmin,
    query: web::Query<ListUsersQuery>,
) -> Result<HttpResponse, AppError> {
    let response = AdminService::new(app_state.get_ref().clone())
        .list_users(query.into_inner())
        .await?;
    audit_admin_action(
        &request,
        app_state.get_ref(),
        &admin,
        ACTION_ADMIN_USERS_LIST,
        json!({
            "page": response.page,
            "per_page": response.per_page,
            "total": response.total,
        }),
    );

    Ok(HttpResponse::Ok().json(response))
}

pub async fn get_user(
    request: HttpRequest,
    app_state: web::Data<AppState>,
    admin: RequireAdmin,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let user_id = path.into_inner();
    let response = AdminService::new(app_state.get_ref().clone())
        .get_user(user_id)
        .await?;
    audit_admin_action(
        &request,
        app_state.get_ref(),
        &admin,
        ACTION_ADMIN_USERS_DETAIL,
        json!({
            "target_user_id": user_id,
        }),
    );

    Ok(HttpResponse::Ok().json(response))
}

pub async fn list_audit_logs(
    request: HttpRequest,
    app_state: web::Data<AppState>,
    admin: RequireAdmin,
    query: web::Query<ListAuditLogsQuery>,
) -> Result<HttpResponse, AppError> {
    let response = AdminService::new(app_state.get_ref().clone())
        .list_audit_logs(query.into_inner())
        .await?;
    audit_admin_action(
        &request,
        app_state.get_ref(),
        &admin,
        ACTION_ADMIN_AUDIT_LOGS_LIST,
        json!({
            "page": response.page,
            "per_page": response.per_page,
            "total": response.total,
        }),
    );

    Ok(HttpResponse::Ok().json(response))
}

pub async fn get_audit_log(
    request: HttpRequest,
    app_state: web::Data<AppState>,
    admin: RequireAdmin,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let audit_log_id = path.into_inner();
    let response = AdminService::new(app_state.get_ref().clone())
        .get_audit_log(audit_log_id)
        .await?;
    audit_admin_action(
        &request,
        app_state.get_ref(),
        &admin,
        ACTION_ADMIN_AUDIT_LOGS_DETAIL,
        json!({
            "audit_log_id": audit_log_id,
        }),
    );

    Ok(HttpResponse::Ok().json(response))
}

pub async fn upstream_health(
    request: HttpRequest,
    app_state: web::Data<AppState>,
    admin: RequireAdmin,
) -> Result<HttpResponse, AppError> {
    let response = AdminService::new(app_state.get_ref().clone())
        .upstream_health()
        .await;
    audit_admin_action(
        &request,
        app_state.get_ref(),
        &admin,
        ACTION_ADMIN_UPSTREAM_HEALTH,
        json!({
            "status": response.status,
        }),
    );

    Ok(HttpResponse::Ok().json(response))
}

pub async fn rate_limit_visibility(
    request: HttpRequest,
    app_state: web::Data<AppState>,
    admin: RequireAdmin,
) -> Result<HttpResponse, AppError> {
    let response = AdminService::new(app_state.get_ref().clone())
        .rate_limit_visibility()
        .await;
    audit_admin_action(
        &request,
        app_state.get_ref(),
        &admin,
        ACTION_ADMIN_RATE_LIMITS_VIEW,
        json!({
            "enabled": response.enabled,
            "redis_status": response.redis.status,
        }),
    );

    Ok(HttpResponse::Ok().json(response))
}

fn audit_admin_action(
    request: &HttpRequest,
    app_state: &AppState,
    admin: &RequireAdmin,
    action: &'static str,
    metadata: Value,
) {
    let event = AuditEvent::from_request(
        request,
        Some(admin.0.user_id),
        action,
        AuditStatus::Success,
        metadata,
    );
    let audit_service = app_state.audit_service.clone();

    actix_web::rt::spawn(async move {
        audit_service.record_safely(event).await;
    });
}
