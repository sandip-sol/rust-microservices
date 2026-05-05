use std::time::Duration;

use actix_web::{App, HttpServer, web};
use sentinel_api_gateway::{
    app::state::AppState,
    cache::redis::init_redis_client,
    config::settings::Settings,
    db::postgres::init_postgres_pool,
    errors::json_config,
    middleware::{logging::RequestLogging, rate_limit::RateLimit, request_id::RequestId},
    repositories::{
        audit_repository::AuditRepository, refresh_token_repository::RefreshTokenRepository,
        user_repository::UserRepository,
    },
    routes::{admin::admin_routes, auth::auth_routes, health::health_routes, proxy::proxy_routes},
    services::{
        audit_service::{ACTION_SYSTEM_STARTUP, AuditService},
        auth_service::AuthService,
    },
    telemetry::tracing::init_tracing,
};
use serde_json::json;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    init_tracing();

    let settings = Settings::from_env();

    let db_pool = init_postgres_pool(&settings.database_url)
        .await
        .expect("failed to connect to PostgreSQL");

    let redis_client =
        init_redis_client(&settings.redis_url).expect("failed to create Redis client");

    let user_repository = UserRepository::new(db_pool.clone());
    let refresh_token_repository = RefreshTokenRepository::new(db_pool.clone());
    let audit_repository = AuditRepository::new(db_pool.clone());
    let auth_service = AuthService::new(
        user_repository.clone(),
        refresh_token_repository.clone(),
        settings.clone(),
    );
    let audit_service = AuditService::new(audit_repository.clone());
    let proxy_http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(settings.proxy_timeout_seconds))
        .build()
        .expect("failed to create proxy HTTP client");

    let app_state = AppState {
        settings: settings.clone(),
        db_pool,
        redis_client,
        user_repository,
        refresh_token_repository,
        audit_repository,
        auth_service,
        audit_service: audit_service.clone(),
        proxy_http_client,
    };

    let bind_addr = settings.app_addr();
    audit_service
        .record_system_event(
            ACTION_SYSTEM_STARTUP,
            json!({
                "bind_addr": bind_addr,
            }),
        )
        .await;

    tracing::info!("starting gateway at {}", bind_addr);

    HttpServer::new(move || {
        App::new()
            .wrap(RateLimit::automatic())
            .wrap(RequestLogging::new())
            .wrap(RequestId::new())
            .app_data(web::Data::new(app_state.clone()))
            .app_data(json_config())
            .app_data(web::PayloadConfig::new(settings.proxy_max_body_bytes))
            .configure(health_routes)
            .configure(auth_routes)
            .configure(admin_routes)
            .configure(proxy_routes)
    })
    .bind(bind_addr)?
    .run()
    .await
}
