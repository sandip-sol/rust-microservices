use actix_web::{web, App, HttpServer};
use sentinel_api_gateway::{
    app::state::AppState,
    cache::redis::init_redis_client,
    config::settings::Settings,
    db::postgres::init_postgres_pool,
    errors::json_config,
    repositories::{
        refresh_token_repository::RefreshTokenRepository, user_repository::UserRepository,
    },
    routes::{auth::auth_routes, health::health_routes},
    services::auth_service::AuthService,
    telemetry::tracing::init_tracing,
};

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
    let auth_service = AuthService::new(
        user_repository.clone(),
        refresh_token_repository.clone(),
        settings.clone(),
    );

    let app_state = AppState {
        settings: settings.clone(),
        db_pool,
        redis_client,
        user_repository,
        refresh_token_repository,
        auth_service,
    };

    let bind_addr = settings.app_addr();

    tracing::info!("starting gateway at {}", bind_addr);

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .app_data(json_config())
            .configure(health_routes)
            .configure(auth_routes)
    })
    .bind(bind_addr)?
    .run()
    .await
}
