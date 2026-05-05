use std::net::TcpListener;

use actix_web::{App, HttpRequest, HttpResponse, HttpServer, http::StatusCode, test, web};
use bytes::Bytes;
use chrono::Utc;
use redis::Client as RedisClient;
use sentinel_api_gateway::{
    app::state::AppState,
    auth::jwt::generate_access_token,
    config::settings::Settings,
    errors::json_config,
    middleware::request_id::{REQUEST_ID_HEADER, RequestId},
    models::user::User,
    repositories::{
        audit_repository::AuditRepository, refresh_token_repository::RefreshTokenRepository,
        user_repository::UserRepository,
    },
    routes::proxy::proxy_routes,
    services::{audit_service::AuditService, auth_service::AuthService},
};
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

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
        proxy_timeout_seconds: 2,
        proxy_forward_auth_header: false,
        proxy_max_body_bytes: 10_485_760,
        rate_limit_enabled: true,
        rate_limit_anon_per_minute: 60,
        rate_limit_auth_per_minute: 300,
        rate_limit_auth_endpoint_per_minute: 10,
        rate_limit_window_seconds: 60,
        rate_limit_redis_prefix: "rate_limit_test".to_string(),
    }
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
        proxy_http_client: reqwest::Client::new(),
    }
}

fn token_for_user(user: &User, settings: &Settings) -> String {
    generate_access_token(user, settings)
        .expect("test token should be generated")
        .0
}

async fn upstream_echo(request: HttpRequest, body: Bytes) -> HttpResponse {
    HttpResponse::Accepted().json(serde_json::json!({
        "method": request.method().as_str(),
        "path": request.path(),
        "query": request.query_string(),
        "body": String::from_utf8_lossy(&body),
        "authorization": request
            .headers()
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        "content_type": request
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        "x_request_id": request
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
        "x_user_id": request
            .headers()
            .get("x-user-id")
            .and_then(|value| value.to_str().ok()),
        "x_user_email": request
            .headers()
            .get("x-user-email")
            .and_then(|value| value.to_str().ok()),
        "x_user_role": request
            .headers()
            .get("x-user-role")
            .and_then(|value| value.to_str().ok()),
    }))
}

async fn start_upstream() -> Option<String> {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("skipping loopback proxy forwarding test because binding failed: {error}");
            return None;
        }
    };
    let address = listener
        .local_addr()
        .expect("test listener should have a local address");

    let server = HttpServer::new(|| App::new().default_service(web::route().to(upstream_echo)))
        .listen(listener)
        .expect("test server should listen")
        .run();
    actix_web::rt::spawn(server);

    Some(format!("http://{address}"))
}

#[actix_web::test]
async fn proxy_forwards_request_context_and_preserves_upstream_response() {
    let Some(upstream_url) = start_upstream().await else {
        return;
    };
    let mut settings = test_settings();
    settings.user_service_url = upstream_url;
    let user = User {
        id: Uuid::new_v4(),
        email: "proxy-user@example.com".to_string(),
        password_hash: "not-used".to_string(),
        role: "admin".to_string(),
        created_at: Utc::now(),
    };
    let token = token_for_user(&user, &settings);
    let request_id = Uuid::new_v4().to_string();

    let app = test::init_service(
        App::new()
            .wrap(RequestId::new())
            .app_data(web::Data::new(test_app_state(settings)))
            .app_data(json_config())
            .configure(proxy_routes),
    )
    .await;

    let request = test::TestRequest::post()
        .uri("/users/profile?include=roles")
        .insert_header(("authorization", format!("Bearer {token}")))
        .insert_header((REQUEST_ID_HEADER, request_id.as_str()))
        .insert_header(("content-type", "application/json"))
        .insert_header(("connection", "keep-alive"))
        .insert_header(("x-user-id", "spoofed-user"))
        .set_payload(r#"{"hello":"gateway"}"#)
        .to_request();

    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(
        response.headers().get(REQUEST_ID_HEADER),
        Some(&request_id.parse().expect("valid header value"))
    );
    let body: Value = test::read_body_json(response).await;
    assert_eq!(body["method"].as_str(), Some("POST"));
    assert_eq!(body["path"].as_str(), Some("/users/profile"));
    assert_eq!(body["query"].as_str(), Some("include=roles"));
    assert_eq!(body["body"].as_str(), Some(r#"{"hello":"gateway"}"#));
    assert_eq!(body["authorization"], Value::Null);
    assert_eq!(body["content_type"].as_str(), Some("application/json"));
    assert_eq!(body["x_request_id"].as_str(), Some(request_id.as_str()));
    assert_eq!(
        body["x_user_id"].as_str(),
        Some(user.id.to_string().as_str())
    );
    assert_eq!(body["x_user_email"].as_str(), Some(user.email.as_str()));
    assert_eq!(body["x_user_role"].as_str(), Some("admin"));
}

#[actix_web::test]
async fn proxy_returns_bad_gateway_when_upstream_connection_fails() {
    let mut settings = test_settings();
    settings.user_service_url = "http://127.0.0.1:9".to_string();
    let user = User {
        id: Uuid::new_v4(),
        email: "proxy-user@example.com".to_string(),
        password_hash: "not-used".to_string(),
        role: "user".to_string(),
        created_at: Utc::now(),
    };
    let token = token_for_user(&user, &settings);

    let app = test::init_service(
        App::new()
            .wrap(RequestId::new())
            .app_data(web::Data::new(test_app_state(settings)))
            .app_data(json_config())
            .configure(proxy_routes),
    )
    .await;

    let request = test::TestRequest::get()
        .uri("/users/profile")
        .insert_header(("authorization", format!("Bearer {token}")))
        .to_request();

    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}
