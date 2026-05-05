use chrono::Utc;
use sentinel_api_gateway::{
    models::audit::{AuditStatus, NewAuditLog},
    repositories::audit_repository::AuditRepository,
    services::audit_service::{ACTION_AUTH_LOGIN, AuditEvent, AuditService},
};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

#[actix_web::test]
async fn audit_repository_persists_queryable_record_when_database_available() {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("skipping audit repository test because DATABASE_URL is not set");
        return;
    };

    let Ok(db_pool) = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
    else {
        eprintln!("skipping audit repository test because DATABASE_URL is unavailable");
        return;
    };

    sqlx::migrate!("./migrations")
        .run(&db_pool)
        .await
        .expect("migrations should run");

    let repository = AuditRepository::new(db_pool.clone());
    let request_id = Uuid::new_v4().to_string();
    let user_id = Uuid::new_v4();

    let audit_log = repository
        .create(NewAuditLog {
            request_id: Some(request_id.clone()),
            user_id: Some(user_id),
            action: ACTION_AUTH_LOGIN.to_string(),
            resource: Some("/auth/login".to_string()),
            status: "success".to_string(),
            ip_address: Some("203.0.113.10".to_string()),
            user_agent: Some("AuditTest/1.0".to_string()),
            metadata: json!({
                "method": "POST",
                "status_code": 200
            }),
        })
        .await
        .expect("audit log should persist");

    let logs = repository
        .list_by_request_id(&request_id)
        .await
        .expect("audit logs should be queryable by request id");

    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].id, audit_log.id);
    assert_eq!(logs[0].request_id.as_deref(), Some(request_id.as_str()));
    assert_eq!(logs[0].user_id, Some(user_id));
    assert_eq!(logs[0].action, ACTION_AUTH_LOGIN);
    assert_eq!(logs[0].status, "success");
    assert_eq!(logs[0].metadata["method"], "POST");

    sqlx::query("DELETE FROM audit_logs WHERE id = $1")
        .bind(audit_log.id)
        .execute(&db_pool)
        .await
        .expect("audit cleanup should succeed");
}

#[actix_web::test]
async fn audit_service_sanitizes_sensitive_metadata_before_persisting_when_database_available() {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("skipping audit service test because DATABASE_URL is not set");
        return;
    };

    let Ok(db_pool) = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
    else {
        eprintln!("skipping audit service test because DATABASE_URL is unavailable");
        return;
    };

    sqlx::migrate!("./migrations")
        .run(&db_pool)
        .await
        .expect("migrations should run");

    let service = AuditService::new(AuditRepository::new(db_pool.clone()));
    let request_id = Uuid::new_v4().to_string();

    let audit_log = service
        .record(AuditEvent {
            request_id: Some(request_id.clone()),
            user_id: None,
            action: ACTION_AUTH_LOGIN.to_string(),
            resource: Some("/auth/login".to_string()),
            status: AuditStatus::Failure,
            ip_address: Some("203.0.113.11".to_string()),
            user_agent: Some("AuditTest/1.0".to_string()),
            metadata: json!({
                "error_kind": "unauthorized",
                "password": "never-store-me",
                "access_token": "never-store-me",
                "nested": {
                    "refresh_token": "never-store-me",
                    "kept": "safe"
                },
                "observed_at": Utc::now()
            }),
        })
        .await
        .expect("audit service should persist sanitized event");

    let metadata_text = audit_log.metadata.to_string();
    assert_eq!(audit_log.metadata["error_kind"], "unauthorized");
    assert_eq!(audit_log.metadata["nested"]["kept"], "safe");
    assert!(!metadata_text.contains("never-store-me"));
    assert!(audit_log.metadata.get("password").is_none());
    assert!(audit_log.metadata.get("access_token").is_none());

    let persisted_metadata: Value =
        sqlx::query_scalar("SELECT metadata FROM audit_logs WHERE id = $1")
            .bind(audit_log.id)
            .fetch_one(&db_pool)
            .await
            .expect("persisted audit metadata should be readable");

    assert_eq!(persisted_metadata, audit_log.metadata);

    sqlx::query("DELETE FROM audit_logs WHERE id = $1")
        .bind(audit_log.id)
        .execute(&db_pool)
        .await
        .expect("audit cleanup should succeed");
}
