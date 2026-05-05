use actix_web::{App, http::StatusCode, test, web};
use chrono::Utc;
use redis::Client as RedisClient;
use sentinel_api_gateway::{
    app::state::AppState,
    auth::jwt::generate_access_token,
    config::settings::Settings,
    errors::json_config,
    middleware::auth::{AuthenticatedUser, RequireAdmin, RequireService, RequireUser},
    models::user::User,
    repositories::{
        refresh_token_repository::RefreshTokenRepository, user_repository::UserRepository,
    },
    routes::auth::auth_routes,
    services::auth_service::AuthService,
};
use serde_json::Value;
use sqlx::{PgPool, postgres::PgPoolOptions};
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
        rate_limit_enabled: true,
        rate_limit_anon_per_minute: 60,
        rate_limit_auth_per_minute: 300,
        rate_limit_auth_endpoint_per_minute: 10,
        rate_limit_window_seconds: 60,
        rate_limit_redis_prefix: "rate_limit_test".to_string(),
    }
}

fn test_app_state() -> AppState {
    let settings = test_settings();
    let db_pool = PgPoolOptions::new()
        .connect_lazy(&settings.database_url)
        .expect("test database URL should be valid");
    test_app_state_with_pool(settings, db_pool)
}

fn test_app_state_with_pool(settings: Settings, db_pool: PgPool) -> AppState {
    let redis_client =
        RedisClient::open(settings.redis_url.as_str()).expect("test Redis URL should be valid");
    let user_repository = UserRepository::new(db_pool.clone());
    let refresh_token_repository = RefreshTokenRepository::new(db_pool.clone());
    let auth_service = AuthService::new(
        user_repository.clone(),
        refresh_token_repository.clone(),
        settings.clone(),
    );

    AppState {
        settings,
        db_pool,
        redis_client,
        user_repository,
        refresh_token_repository,
        auth_service,
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

async fn protected_user(user: AuthenticatedUser) -> actix_web::HttpResponse {
    actix_web::HttpResponse::Ok().json(serde_json::json!({
        "id": user.user_id,
        "email": user.email(),
        "role": user.role_name()
    }))
}

async fn user_role_route(_: RequireUser) -> actix_web::HttpResponse {
    actix_web::HttpResponse::Ok().finish()
}

async fn admin_role_route(_: RequireAdmin) -> actix_web::HttpResponse {
    actix_web::HttpResponse::Ok().finish()
}

async fn service_role_route(_: RequireService) -> actix_web::HttpResponse {
    actix_web::HttpResponse::Ok().finish()
}

fn protected_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/protected", web::get().to(protected_user))
        .route("/protected/user", web::get().to(user_role_route))
        .route("/protected/admin", web::get().to(admin_role_route))
        .route("/protected/service", web::get().to(service_role_route));
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
async fn refresh_rejects_missing_refresh_token_before_database_access() {
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(test_app_state()))
            .app_data(json_config())
            .configure(auth_routes),
    )
    .await;

    let request = test::TestRequest::post()
        .uri("/auth/refresh")
        .set_json(serde_json::json!({}))
        .to_request();

    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn logout_rejects_empty_refresh_token_before_database_access() {
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(test_app_state()))
            .app_data(json_config())
            .configure(auth_routes),
    )
    .await;

    let request = test::TestRequest::post()
        .uri("/auth/logout")
        .set_json(serde_json::json!({
            "refresh_token": "   "
        }))
        .to_request();

    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn me_rejects_missing_bearer_token_before_database_access() {
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(test_app_state()))
            .app_data(json_config())
            .configure(auth_routes),
    )
    .await;

    let request = test::TestRequest::get().uri("/auth/me").to_request();

    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn protected_route_accepts_valid_access_token_without_database_access() {
    let app_state = test_app_state();
    let token = token_for_role("user", &app_state.settings);
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(app_state))
            .app_data(json_config())
            .configure(protected_routes),
    )
    .await;

    let request = test::TestRequest::get()
        .uri("/protected")
        .insert_header(("authorization", format!("Bearer {token}")))
        .to_request();

    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = test::read_body_json(response).await;
    assert_eq!(body["email"].as_str(), Some("user-token@example.com"));
    assert_eq!(body["role"].as_str(), Some("user"));
}

#[actix_web::test]
async fn protected_route_rejects_invalid_access_token_without_database_access() {
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(test_app_state()))
            .app_data(json_config())
            .configure(protected_routes),
    )
    .await;

    let request = test::TestRequest::get()
        .uri("/protected")
        .insert_header(("authorization", "Bearer not-a-jwt"))
        .to_request();

    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn role_gates_return_forbidden_for_insufficient_permissions() {
    let app_state = test_app_state();
    let user_token = token_for_role("user", &app_state.settings);
    let service_token = token_for_role("service", &app_state.settings);
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(app_state))
            .app_data(json_config())
            .configure(protected_routes),
    )
    .await;

    let admin_request = test::TestRequest::get()
        .uri("/protected/admin")
        .insert_header(("authorization", format!("Bearer {user_token}")))
        .to_request();
    let admin_response = test::call_service(&app, admin_request).await;
    assert_eq!(admin_response.status(), StatusCode::FORBIDDEN);

    let user_request = test::TestRequest::get()
        .uri("/protected/user")
        .insert_header(("authorization", format!("Bearer {service_token}")))
        .to_request();
    let user_response = test::call_service(&app, user_request).await;
    assert_eq!(user_response.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn role_gates_allow_expected_roles() {
    let app_state = test_app_state();
    let admin_token = token_for_role("admin", &app_state.settings);
    let service_token = token_for_role("service", &app_state.settings);
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(app_state))
            .app_data(json_config())
            .configure(protected_routes),
    )
    .await;

    let admin_request = test::TestRequest::get()
        .uri("/protected/admin")
        .insert_header(("authorization", format!("Bearer {admin_token}")))
        .to_request();
    let admin_response = test::call_service(&app, admin_request).await;
    assert_eq!(admin_response.status(), StatusCode::OK);

    let user_request = test::TestRequest::get()
        .uri("/protected/user")
        .insert_header(("authorization", format!("Bearer {admin_token}")))
        .to_request();
    let user_response = test::call_service(&app, user_request).await;
    assert_eq!(user_response.status(), StatusCode::OK);

    let service_request = test::TestRequest::get()
        .uri("/protected/service")
        .insert_header(("authorization", format!("Bearer {service_token}")))
        .to_request();
    let service_response = test::call_service(&app, service_request).await;
    assert_eq!(service_response.status(), StatusCode::OK);
}

#[actix_web::test]
async fn auth_refresh_logout_and_me_flow_with_database_when_available() {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("skipping DB-backed auth flow test because DATABASE_URL is not set");
        return;
    };

    let Ok(db_pool) = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
    else {
        eprintln!("skipping DB-backed auth flow test because DATABASE_URL is unavailable");
        return;
    };

    sqlx::migrate!("./migrations")
        .run(&db_pool)
        .await
        .expect("migrations should run");

    let mut settings = test_settings();
    settings.database_url = database_url;
    let email = format!("phase2-{}@example.com", Uuid::new_v4());
    let password = "correct horse battery staple";

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(test_app_state_with_pool(
                settings,
                db_pool.clone(),
            )))
            .app_data(json_config())
            .configure(auth_routes),
    )
    .await;

    let register_request = test::TestRequest::post()
        .uri("/auth/register")
        .set_json(serde_json::json!({
            "email": email.clone(),
            "password": password
        }))
        .to_request();
    let register_response = test::call_service(&app, register_request).await;
    assert_eq!(register_response.status(), StatusCode::CREATED);

    let login_request = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(serde_json::json!({
            "email": email.clone(),
            "password": password
        }))
        .to_request();
    let login_response = test::call_service(&app, login_request).await;
    assert_eq!(login_response.status(), StatusCode::OK);
    let login_body: Value = test::read_body_json(login_response).await;
    let access_token = login_body["access_token"]
        .as_str()
        .expect("login should return an access token")
        .to_string();
    let first_refresh_token = login_body["refresh_token"]
        .as_str()
        .expect("login should return a refresh token")
        .to_string();

    let me_request = test::TestRequest::get()
        .uri("/auth/me")
        .insert_header(("authorization", format!("Bearer {access_token}")))
        .to_request();
    let me_response = test::call_service(&app, me_request).await;
    assert_eq!(me_response.status(), StatusCode::OK);
    let me_body: Value = test::read_body_json(me_response).await;
    assert_eq!(me_body["email"].as_str(), Some(email.as_str()));

    let refresh_request = test::TestRequest::post()
        .uri("/auth/refresh")
        .set_json(serde_json::json!({
            "refresh_token": first_refresh_token.clone()
        }))
        .to_request();
    let refresh_response = test::call_service(&app, refresh_request).await;
    assert_eq!(refresh_response.status(), StatusCode::OK);
    let refresh_body: Value = test::read_body_json(refresh_response).await;
    let rotated_refresh_token = refresh_body["refresh_token"]
        .as_str()
        .expect("refresh should return a rotated refresh token")
        .to_string();
    assert_ne!(first_refresh_token, rotated_refresh_token);

    let reused_refresh_request = test::TestRequest::post()
        .uri("/auth/refresh")
        .set_json(serde_json::json!({
            "refresh_token": first_refresh_token.clone()
        }))
        .to_request();
    let reused_refresh_response = test::call_service(&app, reused_refresh_request).await;
    assert_eq!(reused_refresh_response.status(), StatusCode::UNAUTHORIZED);

    let second_login_request = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(serde_json::json!({
            "email": email.clone(),
            "password": password
        }))
        .to_request();
    let second_login_response = test::call_service(&app, second_login_request).await;
    assert_eq!(second_login_response.status(), StatusCode::OK);
    let second_login_body: Value = test::read_body_json(second_login_response).await;
    let logout_refresh_token = second_login_body["refresh_token"]
        .as_str()
        .expect("second login should return a refresh token")
        .to_string();

    let logout_request = test::TestRequest::post()
        .uri("/auth/logout")
        .set_json(serde_json::json!({
            "refresh_token": logout_refresh_token.clone()
        }))
        .to_request();
    let logout_response = test::call_service(&app, logout_request).await;
    assert_eq!(logout_response.status(), StatusCode::NO_CONTENT);

    let logged_out_refresh_request = test::TestRequest::post()
        .uri("/auth/refresh")
        .set_json(serde_json::json!({
            "refresh_token": logout_refresh_token.clone()
        }))
        .to_request();
    let logged_out_refresh_response = test::call_service(&app, logged_out_refresh_request).await;
    assert_eq!(
        logged_out_refresh_response.status(),
        StatusCode::UNAUTHORIZED
    );

    sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(email)
        .execute(&db_pool)
        .await
        .expect("test user cleanup should succeed");
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
