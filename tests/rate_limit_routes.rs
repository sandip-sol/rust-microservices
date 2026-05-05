use actix_web::{App, HttpResponse, http::StatusCode, test, web};
use chrono::Utc;
use redis::Client as RedisClient;
use sentinel_api_gateway::{
    app::state::AppState,
    auth::jwt::generate_access_token,
    config::settings::Settings,
    errors::json_config,
    middleware::{auth::AuthenticatedUser, rate_limit::RateLimit},
    models::user::User,
    repositories::{
        audit_repository::AuditRepository, refresh_token_repository::RefreshTokenRepository,
        user_repository::UserRepository,
    },
    routes::auth::auth_routes,
    services::{audit_service::AuditService, auth_service::AuthService},
};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

fn test_settings(prefix: String) -> Settings {
    Settings {
        app_host: "127.0.0.1".to_string(),
        app_port: 8080,
        database_url: "postgres://postgres:postgres@localhost/sentinel_test".to_string(),
        redis_url: std::env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string()),
        jwt_access_secret: "test-access-secret".to_string(),
        jwt_refresh_secret: "test-refresh-secret".to_string(),
        access_token_ttl_minutes: 15,
        refresh_token_ttl_days: 7,
        user_service_url: "http://localhost:8081".to_string(),
        payment_service_url: "http://localhost:8082".to_string(),
        rate_limit_enabled: true,
        rate_limit_anon_per_minute: 1,
        rate_limit_auth_per_minute: 1,
        rate_limit_auth_endpoint_per_minute: 1,
        rate_limit_window_seconds: 60,
        rate_limit_redis_prefix: prefix,
    }
}

async fn redis_available(redis_url: &str) -> bool {
    let Ok(client) = RedisClient::open(redis_url) else {
        return false;
    };
    let Ok(mut connection) = client.get_multiplexed_async_connection().await else {
        return false;
    };
    redis::cmd("PING")
        .query_async::<String>(&mut connection)
        .await
        .is_ok()
}

fn test_app_state(settings: Settings) -> AppState {
    let db_pool = PgPoolOptions::new()
        .connect_lazy(&settings.database_url)
        .expect("test database URL should be valid");
    let redis_client =
        RedisClient::open(settings.redis_url.as_str()).expect("test Redis URL should be valid");
    let user_repository = UserRepository::new(db_pool.clone());
    let refresh_token_repository = RefreshTokenRepository::new(db_pool.clone());
    let audit_repository = AuditRepository::new(db_pool.clone());
    let auth_service = AuthService::new(
        user_repository.clone(),
        refresh_token_repository.clone(),
        settings.clone(),
    );
    let audit_service = AuditService::new(audit_repository.clone());

    AppState {
        settings,
        db_pool,
        redis_client,
        user_repository,
        refresh_token_repository,
        audit_repository,
        auth_service,
        audit_service,
    }
}

fn token_for_role(role: &str, settings: &Settings) -> String {
    let user = User {
        id: Uuid::new_v4(),
        email: format!("{role}-token@example.com"),
        password_hash: "not-used".to_string(),
        role: role.to_string(),
        created_at: Utc::now(),
    };

    generate_access_token(&user, settings)
        .expect("test token should be generated")
        .0
}

async fn ok() -> HttpResponse {
    HttpResponse::Ok().finish()
}

async fn protected(_: AuthenticatedUser) -> HttpResponse {
    HttpResponse::Ok().finish()
}

fn api_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/health", web::get().to(ok))
        .route("/public", web::get().to(ok))
        .route("/protected", web::get().to(protected));
}

#[actix_web::test]
async fn anonymous_requests_are_limited_by_ip() {
    let settings = test_settings(format!("rate_limit_test_{}", Uuid::new_v4().simple()));
    if !redis_available(&settings.redis_url).await {
        eprintln!("skipping Redis-backed rate limit test because Redis is unavailable");
        return;
    }

    let app = test::init_service(
        App::new()
            .wrap(RateLimit::automatic())
            .app_data(web::Data::new(test_app_state(settings)))
            .configure(api_routes),
    )
    .await;

    let first = test::TestRequest::get()
        .uri("/public")
        .peer_addr("203.0.113.10:5000".parse().expect("valid socket address"))
        .to_request();
    let first_response = test::call_service(&app, first).await;
    assert_eq!(first_response.status(), StatusCode::OK);
    assert_eq!(
        first_response.headers().get("x-ratelimit-remaining"),
        Some(&"0".parse().expect("valid header"))
    );

    let second = test::TestRequest::get()
        .uri("/public")
        .peer_addr("203.0.113.10:5001".parse().expect("valid socket address"))
        .to_request();
    let second_response = test::call_service(&app, second).await;
    assert_eq!(second_response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(second_response.headers().contains_key("retry-after"));
}

#[actix_web::test]
async fn authenticated_requests_are_limited_by_user() {
    let settings = test_settings(format!("rate_limit_test_{}", Uuid::new_v4().simple()));
    if !redis_available(&settings.redis_url).await {
        eprintln!("skipping Redis-backed rate limit test because Redis is unavailable");
        return;
    }
    let first_token = token_for_role("user", &settings);
    let second_token = token_for_role("admin", &settings);

    let app = test::init_service(
        App::new()
            .wrap(RateLimit::automatic())
            .app_data(web::Data::new(test_app_state(settings)))
            .configure(api_routes),
    )
    .await;

    let first = test::TestRequest::get()
        .uri("/protected")
        .insert_header(("authorization", format!("Bearer {first_token}")))
        .to_request();
    let first_response = test::call_service(&app, first).await;
    assert_eq!(first_response.status(), StatusCode::OK);

    let repeated = test::TestRequest::get()
        .uri("/protected")
        .insert_header(("authorization", format!("Bearer {first_token}")))
        .to_request();
    let repeated_response = test::call_service(&app, repeated).await;
    assert_eq!(repeated_response.status(), StatusCode::TOO_MANY_REQUESTS);

    let other_user = test::TestRequest::get()
        .uri("/protected")
        .insert_header(("authorization", format!("Bearer {second_token}")))
        .to_request();
    let other_user_response = test::call_service(&app, other_user).await;
    assert_eq!(other_user_response.status(), StatusCode::OK);
}

#[actix_web::test]
async fn auth_endpoints_use_the_stricter_limit() {
    let settings = test_settings(format!("rate_limit_test_{}", Uuid::new_v4().simple()));
    if !redis_available(&settings.redis_url).await {
        eprintln!("skipping Redis-backed rate limit test because Redis is unavailable");
        return;
    }

    let app = test::init_service(
        App::new()
            .wrap(RateLimit::automatic())
            .app_data(web::Data::new(test_app_state(settings)))
            .app_data(json_config())
            .configure(auth_routes),
    )
    .await;

    let first = test::TestRequest::post()
        .uri("/auth/register")
        .peer_addr("203.0.113.20:5000".parse().expect("valid socket address"))
        .set_json(serde_json::json!({
            "email": "not-an-email",
            "password": "password123"
        }))
        .to_request();
    let first_response = test::call_service(&app, first).await;
    assert_eq!(first_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        first_response.headers().get("x-ratelimit-limit"),
        Some(&"1".parse().expect("valid header"))
    );

    let second = test::TestRequest::post()
        .uri("/auth/register")
        .peer_addr("203.0.113.20:5001".parse().expect("valid socket address"))
        .set_json(serde_json::json!({
            "email": "also-not-an-email",
            "password": "password123"
        }))
        .to_request();
    let second_response = test::call_service(&app, second).await;
    assert_eq!(second_response.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[actix_web::test]
async fn health_is_not_rate_limited() {
    let settings = test_settings(format!("rate_limit_test_{}", Uuid::new_v4().simple()));
    if !redis_available(&settings.redis_url).await {
        eprintln!("skipping Redis-backed rate limit test because Redis is unavailable");
        return;
    }

    let app = test::init_service(
        App::new()
            .wrap(RateLimit::automatic())
            .app_data(web::Data::new(test_app_state(settings)))
            .configure(api_routes),
    )
    .await;

    let first = test::TestRequest::get().uri("/health").to_request();
    let first_response = test::call_service(&app, first).await;
    assert_eq!(first_response.status(), StatusCode::OK);
    assert!(!first_response.headers().contains_key("x-ratelimit-limit"));

    let second = test::TestRequest::get().uri("/health").to_request();
    let second_response = test::call_service(&app, second).await;
    assert_eq!(second_response.status(), StatusCode::OK);
    assert!(!second_response.headers().contains_key("x-ratelimit-limit"));
}
