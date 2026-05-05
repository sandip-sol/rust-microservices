use actix_web::{HttpRequest, HttpResponse, web};

use crate::{
    app::state::AppState,
    errors::AppError,
    models::auth::{LoginRequest, LogoutRequest, RefreshRequest, RegisterRequest},
};

pub async fn register(
    app_state: web::Data<AppState>,
    payload: web::Json<RegisterRequest>,
) -> Result<HttpResponse, AppError> {
    let user = app_state
        .auth_service
        .register(payload.into_inner())
        .await?;
    Ok(HttpResponse::Created().json(user))
}

pub async fn login(
    app_state: web::Data<AppState>,
    payload: web::Json<LoginRequest>,
) -> Result<HttpResponse, AppError> {
    let response = app_state.auth_service.login(payload.into_inner()).await?;
    Ok(HttpResponse::Ok().json(response))
}

pub async fn refresh(
    app_state: web::Data<AppState>,
    payload: web::Json<RefreshRequest>,
) -> Result<HttpResponse, AppError> {
    let response = app_state.auth_service.refresh(payload.into_inner()).await?;
    Ok(HttpResponse::Ok().json(response))
}

pub async fn logout(
    app_state: web::Data<AppState>,
    payload: web::Json<LogoutRequest>,
) -> Result<HttpResponse, AppError> {
    app_state.auth_service.logout(payload.into_inner()).await?;
    Ok(HttpResponse::NoContent().finish())
}

pub async fn me(
    app_state: web::Data<AppState>,
    request: HttpRequest,
) -> Result<HttpResponse, AppError> {
    let access_token = bearer_token(&request)?;
    let user = app_state.auth_service.current_user(access_token).await?;
    Ok(HttpResponse::Ok().json(user))
}

fn bearer_token(request: &HttpRequest) -> Result<&str, AppError> {
    let header = request
        .headers()
        .get("authorization")
        .ok_or_else(|| AppError::Unauthorized("missing bearer token".to_string()))?
        .to_str()
        .map_err(|_| AppError::Unauthorized("invalid bearer token".to_string()))?;

    header
        .strip_prefix("Bearer ")
        .filter(|token| !token.trim().is_empty() && token.trim() == *token)
        .ok_or_else(|| AppError::Unauthorized("invalid bearer token".to_string()))
}
