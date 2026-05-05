use actix_web::{web, HttpResponse};

use crate::{
    app::state::AppState,
    errors::AppError,
    models::auth::{LoginRequest, RegisterRequest},
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
