use actix_web::{HttpRequest, HttpResponse, ResponseError, web};
use serde_json::json;
use uuid::Uuid;

use crate::{
    app::state::AppState,
    errors::AppError,
    middleware::auth::AuthenticatedUser,
    models::audit::AuditStatus,
    models::auth::{LoginRequest, LogoutRequest, RefreshRequest, RegisterRequest},
    services::audit_service::{
        ACTION_AUTH_LOGIN, ACTION_AUTH_LOGOUT, ACTION_AUTH_ME, ACTION_AUTH_REFRESH,
        ACTION_AUTH_REGISTER, AuditEvent,
    },
};

pub async fn register(
    request: HttpRequest,
    app_state: web::Data<AppState>,
    payload: web::Json<RegisterRequest>,
) -> Result<HttpResponse, AppError> {
    let result = app_state.auth_service.register(payload.into_inner()).await;
    audit_auth_result(
        &request,
        &app_state,
        ACTION_AUTH_REGISTER,
        201,
        result.as_ref().ok().map(|user| user.id),
        &result,
    )
    .await;

    let user = result?;
    Ok(HttpResponse::Created().json(user))
}

pub async fn login(
    request: HttpRequest,
    app_state: web::Data<AppState>,
    payload: web::Json<LoginRequest>,
) -> Result<HttpResponse, AppError> {
    let result = app_state.auth_service.login(payload.into_inner()).await;
    audit_auth_result(
        &request,
        &app_state,
        ACTION_AUTH_LOGIN,
        200,
        result.as_ref().ok().map(|response| response.user.id),
        &result,
    )
    .await;

    let response = result?;
    Ok(HttpResponse::Ok().json(response))
}

pub async fn refresh(
    request: HttpRequest,
    app_state: web::Data<AppState>,
    payload: web::Json<RefreshRequest>,
) -> Result<HttpResponse, AppError> {
    let result = app_state.auth_service.refresh(payload.into_inner()).await;
    audit_auth_result(
        &request,
        &app_state,
        ACTION_AUTH_REFRESH,
        200,
        result.as_ref().ok().map(|response| response.user.id),
        &result,
    )
    .await;

    let response = result?;
    Ok(HttpResponse::Ok().json(response))
}

pub async fn logout(
    request: HttpRequest,
    app_state: web::Data<AppState>,
    payload: web::Json<LogoutRequest>,
) -> Result<HttpResponse, AppError> {
    let result = app_state.auth_service.logout(payload.into_inner()).await;
    audit_auth_result(
        &request,
        &app_state,
        ACTION_AUTH_LOGOUT,
        204,
        result.as_ref().ok().copied().flatten(),
        &result,
    )
    .await;

    result?;
    Ok(HttpResponse::NoContent().finish())
}

pub async fn me(
    request: HttpRequest,
    app_state: web::Data<AppState>,
    user: AuthenticatedUser,
) -> Result<HttpResponse, AppError> {
    app_state
        .audit_service
        .record_safely(AuditEvent::from_request(
            &request,
            Some(user.user_id),
            ACTION_AUTH_ME,
            AuditStatus::Success,
            json!({
                "role": user.role_name(),
            }),
        ))
        .await;

    Ok(HttpResponse::Ok().json(user.into_response()))
}

async fn audit_auth_result<T>(
    request: &HttpRequest,
    app_state: &AppState,
    action: &'static str,
    success_status_code: u16,
    user_id: Option<Uuid>,
    result: &Result<T, AppError>,
) {
    let (status, metadata) = match result {
        Ok(_) => (
            AuditStatus::Success,
            json!({
                "status_code": success_status_code,
            }),
        ),
        Err(error) => (
            AuditStatus::Failure,
            json!({
                "status_code": error.status_code().as_u16(),
                "error_kind": app_error_kind(error),
            }),
        ),
    };

    app_state
        .audit_service
        .record_safely(AuditEvent::from_request(
            request, user_id, action, status, metadata,
        ))
        .await;
}

fn app_error_kind(error: &AppError) -> &'static str {
    match error {
        AppError::BadRequest(_) => "bad_request",
        AppError::Unauthorized(_) => "unauthorized",
        AppError::Forbidden(_) => "forbidden",
        AppError::NotFound(_) => "not_found",
        AppError::Conflict(_) => "conflict",
        AppError::RateLimitExceeded(_) => "rate_limit_exceeded",
        AppError::BadGateway(_) => "bad_gateway",
        AppError::GatewayTimeout(_) => "gateway_timeout",
        AppError::Database => "database",
        AppError::PasswordHash => "password_hash",
        AppError::TokenCreation => "token_creation",
        AppError::Internal => "internal",
    }
}
