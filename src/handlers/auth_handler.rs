use actix_web::{HttpResponse, web};

use crate::{
    app::state::AppState,
    errors::AppError,
    middleware::auth::AuthenticatedUser,
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

pub async fn me(user: AuthenticatedUser) -> Result<HttpResponse, AppError> {
    Ok(HttpResponse::Ok().json(user.into_response()))
}
