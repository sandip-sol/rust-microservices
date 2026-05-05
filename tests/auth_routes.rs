use actix_web::{App, http::StatusCode, test, web};
use redis::Client as RedisClient;
use sentinel_api_gateway::{
    app::state::AppState, config::settings::Settings, errors::json_config,
    repositories::user_repository::UserRepository, routes::auth::auth_routes,
    services::auth_service::AuthService,
};
use sqlx::postgres::PgPoolOptions;

fn test_settings() -> Settings {
    Settings {
        app_host: "127.0.0.1".to_string(),
        app_port: 8080,
        database_url: "postgres://postgres:postgres@localhost/sentinel_test".to_string(),
        redis_url: "redis://127.0.0.1/".to_string(),
        jwt_access_secret: "test-access-secret".to_string(),
        jwt_refresh_secret: "test-refresh-secret".to_string(),
        access_token_ttl_minutes: 15,
        refresh_token_ttl_days: 7,
        user_service_url: "http://localhost:8081".to_string(),
        payment_service_url: "http://localhost:8082".to_string(),
    }
}

fn test_app_state() -> AppState {
    let settings = test_settings();
    let db_pool = PgPoolOptions::new()
        .connect_lazy(&settings.database_url)
        .expect("test database URL should be valid");
    let redis_client =
        RedisClient::open(settings.redis_url.as_str()).expect("test Redis URL should be valid");
    let user_repository = UserRepository::new(db_pool.clone());
    let auth_service = AuthService::new(user_repository.clone(), settings.clone());

    AppState {
        settings,
        db_pool,
        redis_client,
        user_repository,
        auth_service,
    }
}

#[actix_web::test]
async fn register_rejects_invalid_payload_before_database_access() {
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(test_app_state()))
            .app_data(json_config())
            .configure(auth_routes),
    )
    .await;

    let request = test::TestRequest::post()
        .uri("/auth/register")
        .set_json(serde_json::json!({
            "email": "not-an-email",
            "password": "password123"
        }))
        .to_request();

    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn login_rejects_invalid_json_body() {
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(test_app_state()))
            .app_data(json_config())
            .configure(auth_routes),
    )
    .await;

    let request = test::TestRequest::post()
        .uri("/auth/login")
        .insert_header(("content-type", "application/json"))
        .set_payload("{")
        .to_request();

    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
