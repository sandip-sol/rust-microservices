use std::time::Duration;

use actix_web::{App, http::StatusCode, test, web};
use chrono::Utc;
use redis::Client as RedisClient;
use sentinel_api_gateway::{
    app::state::AppState,
    auth::jwt::generate_access_token,
    config::settings::Settings,
    errors::json_config,
    middleware::request_id::{REQUEST_ID_HEADER, RequestId},
    models::{audit::NewAuditLog, user::User},
    repositories::{
        audit_repository::AuditRepository, refresh_token_repository::RefreshTokenRepository,
        user_repository::UserRepository,
    },
    routes::admin::admin_routes,
    services::{audit_service::AuditService, auth_service::AuthService},
};
use serde_json::{Value, json};
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
        user_service_url: "http://127.0.0.1:9".to_string(),
        payment_service_url: "http://127.0.0.1:9".to_string(),
        proxy_timeout_seconds: 1,
        proxy_forward_auth_header: false,
        proxy_max_body_bytes: 10_485_760,
        rate_limit_enabled: true,
        rate_limit_anon_per_minute: 60,
        rate_limit_auth_per_minute: 300,
        rate_limit_auth_endpoint_per_minute: 10,
        rate_limit_window_seconds: 60,
        rate_limit_redis_prefix: format!("rate_limit_test_{}", Uuid::new_v4().simple()),
    }
}

fn test_app_state(settings: Settings) -> AppState {
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
    let audit_repository = AuditRepository::new(db_pool.clone());
    let auth_service = AuthService::new(
        user_repository.clone(),
        refresh_token_repository.clone(),
        settings.clone(),
    );
    let audit_service = AuditService::new(audit_repository.clone());
    let proxy_http_client = reqwest::Client::builder()
        .timeout(Duration::from_millis(200))
        .build()
        .expect("test HTTP client should build");

    AppState {
        settings,
        db_pool,
        redis_client,
        user_repository,
        refresh_token_repository,
        audit_repository,
        auth_service,
        audit_service,
        proxy_http_client,
    }
}

fn token_for_role(role: &str, settings: &Settings) -> String {
    let user = User {
        id: Uuid::new_v4(),
        email: format!("{role}-admin-test@example.com"),
        password_hash: "not-used".to_string(),
        role: role.to_string(),
        created_at: Utc::now(),
    };

    generate_access_token(&user, settings)
        .expect("test token should be generated")
        .0
}

async fn database_pool() -> Option<PgPool> {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("skipping DB-backed admin test because DATABASE_URL is not set");
        return None;
    };

    let Ok(db_pool) = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
    else {
        eprintln!("skipping DB-backed admin test because DATABASE_URL is unavailable");
        return None;
    };

    sqlx::migrate!("./migrations")
        .run(&db_pool)
        .await
        .expect("migrations should run");

    Some(db_pool)
}

#[actix_web::test]
async fn admin_routes_require_access_token() {
    let app = test::init_service(
        App::new()
            .wrap(RequestId::new())
            .app_data(web::Data::new(test_app_state(test_settings())))
            .app_data(json_config())
            .configure(admin_routes),
    )
    .await;

    let missing = test::TestRequest::get()
        .uri("/admin/rate-limits")
        .to_request();
    let missing_response = test::call_service(&app, missing).await;
    assert_eq!(missing_response.status(), StatusCode::UNAUTHORIZED);

    let invalid = test::TestRequest::get()
        .uri("/admin/rate-limits")
        .insert_header(("authorization", "Bearer not-a-jwt"))
        .to_request();
    let invalid_response = test::call_service(&app, invalid).await;
    assert_eq!(invalid_response.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn admin_routes_reject_normal_user_role() {
    let app_state = test_app_state(test_settings());
    let token = token_for_role("user", &app_state.settings);
    let app = test::init_service(
        App::new()
            .wrap(RequestId::new())
            .app_data(web::Data::new(app_state))
            .app_data(json_config())
            .configure(admin_routes),
    )
    .await;

    let request = test::TestRequest::get()
        .uri("/admin/rate-limits")
        .insert_header(("authorization", format!("Bearer {token}")))
        .to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn admin_can_view_rate_limit_visibility_without_secret_material() {
    let mut settings = test_settings();
    settings.jwt_access_secret = "access-secret-that-must-not-leak".to_string();
    settings.jwt_refresh_secret = "refresh-secret-that-must-not-leak".to_string();
    let app_state = test_app_state(settings);
    let token = token_for_role("admin", &app_state.settings);
    let app = test::init_service(
        App::new()
            .wrap(RequestId::new())
            .app_data(web::Data::new(app_state))
            .app_data(json_config())
            .configure(admin_routes),
    )
    .await;

    let request = test::TestRequest::get()
        .uri("/admin/rate-limits")
        .insert_header(("authorization", format!("Bearer {token}")))
        .to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = test::read_body(response).await;
    let body_text = String::from_utf8_lossy(&body);
    assert!(body_text.contains("authenticated"));
    assert!(!body_text.contains("access-secret-that-must-not-leak"));
    assert!(!body_text.contains("refresh-secret-that-must-not-leak"));
    assert!(!body_text.contains(&token));
}

#[actix_web::test]
async fn admin_user_endpoints_are_paginated_and_never_expose_password_hashes() {
    let Some(db_pool) = database_pool().await else {
        return;
    };

    let mut settings = test_settings();
    settings.database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL should be set");
    let user_id = Uuid::new_v4();
    let admin_id = Uuid::new_v4();
    let user_email = format!("admin-user-{}@example.com", user_id.simple());
    let admin_email = format!("admin-user-{}@example.com", admin_id.simple());
    let password_hash = "password-hash-that-must-not-leak";

    sqlx::query(
        r#"
        INSERT INTO users (id, email, password_hash, role, created_at)
        VALUES ($1, $2, $3, 'user', NOW()), ($4, $5, $3, 'admin', NOW())
        "#,
    )
    .bind(user_id)
    .bind(&user_email)
    .bind(password_hash)
    .bind(admin_id)
    .bind(&admin_email)
    .execute(&db_pool)
    .await
    .expect("test users should insert");

    let app_state = test_app_state_with_pool(settings, db_pool.clone());
    let token = token_for_role("admin", &app_state.settings);
    let list_request_id = Uuid::new_v4().to_string();
    let detail_request_id = Uuid::new_v4().to_string();
    let app = test::init_service(
        App::new()
            .wrap(RequestId::new())
            .app_data(web::Data::new(app_state))
            .app_data(json_config())
            .configure(admin_routes),
    )
    .await;

    let request = test::TestRequest::get()
        .uri("/admin/users?role=user&per_page=5")
        .insert_header(("authorization", format!("Bearer {token}")))
        .insert_header((REQUEST_ID_HEADER, list_request_id.clone()))
        .to_request();
    let response = test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = test::read_body_json(response).await;
    assert!(body["total"].as_i64().expect("total should be numeric") >= 1);
    assert!(
        body["items"]
            .as_array()
            .expect("items should be an array")
            .iter()
            .any(|item| item["id"] == user_id.to_string())
    );
    let body_text = serde_json::to_string(&body).expect("body should serialize");
    assert!(!body_text.contains("password_hash"));
    assert!(!body_text.contains(password_hash));

    let detail_request = test::TestRequest::get()
        .uri(&format!("/admin/users/{user_id}"))
        .insert_header(("authorization", format!("Bearer {token}")))
        .insert_header((REQUEST_ID_HEADER, detail_request_id.clone()))
        .to_request();
    let detail_response = test::call_service(&app, detail_request).await;
    assert_eq!(detail_response.status(), StatusCode::OK);
    let detail_text = String::from_utf8_lossy(&test::read_body(detail_response).await).to_string();
    assert!(detail_text.contains(&user_email));
    assert!(!detail_text.contains("password_hash"));
    assert!(!detail_text.contains(password_hash));

    actix_web::rt::time::sleep(Duration::from_millis(50)).await;
    sqlx::query("DELETE FROM audit_logs WHERE request_id = ANY($1)")
        .bind(&[list_request_id, detail_request_id])
        .execute(&db_pool)
        .await
        .expect("admin audit logs should clean up");
    sqlx::query("DELETE FROM users WHERE id = ANY($1)")
        .bind(&[user_id, admin_id])
        .execute(&db_pool)
        .await
        .expect("test users should clean up");
}

#[actix_web::test]
async fn admin_audit_log_endpoint_filters_and_sanitizes_metadata() {
    let Some(db_pool) = database_pool().await else {
        return;
    };

    let mut settings = test_settings();
    settings.database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL should be set");
    let request_id = Uuid::new_v4().to_string();
    let other_request_id = Uuid::new_v4().to_string();
    let repository = AuditRepository::new(db_pool.clone());
    let sensitive_log = repository
        .create(NewAuditLog {
            request_id: Some(request_id.clone()),
            user_id: Some(Uuid::new_v4()),
            action: "auth.login".to_string(),
            resource: Some("/auth/login".to_string()),
            status: "success".to_string(),
            ip_address: Some("203.0.113.10".to_string()),
            user_agent: Some("AdminAuditTest/1.0".to_string()),
            metadata: json!({
                "method": "POST",
                "password": "never-expose-me",
                "access_token": "never-expose-me",
                "nested": {
                    "authorization_header": "Bearer never-expose-me",
                    "kept": "safe"
                }
            }),
        })
        .await
        .expect("test audit log should insert");
    let other_log = repository
        .create(NewAuditLog {
            request_id: Some(other_request_id),
            user_id: None,
            action: "auth.login".to_string(),
            resource: Some("/auth/login".to_string()),
            status: "failure".to_string(),
            ip_address: None,
            user_agent: None,
            metadata: json!({}),
        })
        .await
        .expect("other test audit log should insert");

    let app_state = test_app_state_with_pool(settings, db_pool.clone());
    let token = token_for_role("admin", &app_state.settings);
    let list_admin_request_id = Uuid::new_v4().to_string();
    let detail_admin_request_id = Uuid::new_v4().to_string();
    let app = test::init_service(
        App::new()
            .wrap(RequestId::new())
            .app_data(web::Data::new(app_state))
            .app_data(json_config())
            .configure(admin_routes),
    )
    .await;

    let list_request = test::TestRequest::get()
        .uri(&format!(
            "/admin/audit-logs?request_id={request_id}&status=success"
        ))
        .insert_header((REQUEST_ID_HEADER, list_admin_request_id.clone()))
        .insert_header(("authorization", format!("Bearer {token}")))
        .to_request();
    let list_response = test::call_service(&app, list_request).await;
    assert_eq!(list_response.status(), StatusCode::OK);
    let list_body: Value = test::read_body_json(list_response).await;
    assert_eq!(list_body["total"], 1);
    assert_eq!(list_body["items"][0]["id"], sensitive_log.id.to_string());
    assert_eq!(list_body["items"][0]["metadata"]["nested"]["kept"], "safe");
    let list_text = serde_json::to_string(&list_body).expect("body should serialize");
    assert!(!list_text.contains("never-expose-me"));
    assert!(!list_text.contains("authorization_header"));
    assert!(!list_text.contains("access_token"));

    let detail_request = test::TestRequest::get()
        .uri(&format!("/admin/audit-logs/{}", sensitive_log.id))
        .insert_header(("authorization", format!("Bearer {token}")))
        .insert_header((REQUEST_ID_HEADER, detail_admin_request_id.clone()))
        .to_request();
    let detail_response = test::call_service(&app, detail_request).await;
    assert_eq!(detail_response.status(), StatusCode::OK);
    let detail_text = String::from_utf8_lossy(&test::read_body(detail_response).await).to_string();
    assert!(!detail_text.contains("never-expose-me"));
    assert!(!detail_text.contains("authorization_header"));

    actix_web::rt::time::sleep(Duration::from_millis(50)).await;
    sqlx::query("DELETE FROM audit_logs WHERE id = ANY($1)")
        .bind(&[sensitive_log.id, other_log.id])
        .execute(&db_pool)
        .await
        .expect("test audit logs should clean up");
    sqlx::query("DELETE FROM audit_logs WHERE request_id = ANY($1)")
        .bind(&[list_admin_request_id, detail_admin_request_id])
        .execute(&db_pool)
        .await
        .expect("admin audit logs should clean up");
}
