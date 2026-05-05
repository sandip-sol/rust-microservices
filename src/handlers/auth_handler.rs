use actix_web::{web, HttpResponse, Responder};

use crate::{
    app::state::AppState,
    models::auth::{LoginRequest, RegisterRequest},
    repositories::user_repository::UserRepository,
    services::auth_service::AuthService,
};

pub async fn register(
    app_state: web::Data<AppState>,
    payload: web::Json<RegisterRequest>,
) -> impl Responder {
    let user_repo = UserRepository::new(app_state.db_pool.clone());
    let auth_service = AuthService::new(user_repo, app_state.settings.clone());

    match auth_service.register(payload.into_inner()).await {
        Ok(user) => HttpResponse::Created().json(user),
        Err(message) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": message
        })),
    }
}

pub async fn login(
    app_state: web::Data<AppState>,
    payload: web::Json<LoginRequest>,
) -> impl Responder {
    let user_repo = UserRepository::new(app_state.db_pool.clone());
    let auth_service = AuthService::new(user_repo, app_state.settings.clone());

    match auth_service.login(payload.into_inner()).await {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(message) => HttpResponse::Unauthorized().json(serde_json::json!({
            "error": message
        })),
    }
}