use std::net::SocketAddr;

use actix_web::{
    HttpMessage, HttpRequest,
    http::header::{HeaderName, USER_AGENT},
};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::{
    middleware::{request_context::RequestContext, request_id::REQUEST_ID_HEADER},
    models::audit::{AuditLog, AuditStatus, NewAuditLog},
    repositories::audit_repository::AuditRepository,
};

const MAX_METADATA_STRING_LEN: usize = 512;
const SENSITIVE_KEY_PARTS: [&str; 7] = [
    "password",
    "token",
    "authorization",
    "credential",
    "secret",
    "hash",
    "cookie",
];

pub const ACTION_AUTH_REGISTER: &str = "auth.register";
pub const ACTION_AUTH_LOGIN: &str = "auth.login";
pub const ACTION_AUTH_REFRESH: &str = "auth.refresh";
pub const ACTION_AUTH_LOGOUT: &str = "auth.logout";
pub const ACTION_AUTH_ME: &str = "auth.me";
pub const ACTION_AUTH_TOKEN_REJECTED: &str = "auth.access_token.rejected";
pub const ACTION_AUTHORIZATION_DENIED: &str = "authorization.denied";
pub const ACTION_RATE_LIMIT_EXCEEDED: &str = "rate_limit.exceeded";
pub const ACTION_PROXY_FAILURE: &str = "proxy.failure";
pub const ACTION_SYSTEM_STARTUP: &str = "system.startup";

#[derive(Clone)]
pub struct AuditService {
    repository: AuditRepository,
}

impl AuditService {
    pub fn new(repository: AuditRepository) -> Self {
        Self { repository }
    }

    pub async fn record(&self, event: AuditEvent) -> Result<AuditLog, sqlx::Error> {
        self.repository.create(event.into_new_audit_log()).await
    }

    pub async fn record_safely(&self, event: AuditEvent) {
        if let Err(error) = self.record(event).await {
            tracing::error!(error = %error, "audit log write failed");
        }
    }

    pub fn record_request_event_detached(
        &self,
        request: &HttpRequest,
        user_id: Option<Uuid>,
        action: impl Into<String>,
        status: AuditStatus,
        metadata: Value,
    ) {
        let event = AuditEvent::from_request(request, user_id, action, status, metadata);
        let service = self.clone();

        actix_web::rt::spawn(async move {
            service.record_safely(event).await;
        });
    }

    pub async fn record_system_event(&self, action: impl Into<String>, metadata: Value) {
        self.record_safely(AuditEvent {
            request_id: None,
            user_id: None,
            action: action.into(),
            resource: None,
            status: AuditStatus::Success,
            ip_address: None,
            user_agent: None,
            metadata,
        })
        .await;
    }
}

#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub request_id: Option<String>,
    pub user_id: Option<Uuid>,
    pub action: String,
    pub resource: Option<String>,
    pub status: AuditStatus,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub metadata: Value,
}

impl AuditEvent {
    pub fn from_request(
        request: &HttpRequest,
        user_id: Option<Uuid>,
        action: impl Into<String>,
        status: AuditStatus,
        metadata: Value,
    ) -> Self {
        Self {
            request_id: request_id(request),
            user_id,
            action: action.into(),
            resource: Some(request.path().to_string()),
            status,
            ip_address: client_ip(request),
            user_agent: user_agent(request),
            metadata: add_request_metadata(request, metadata),
        }
    }

    fn into_new_audit_log(self) -> NewAuditLog {
        NewAuditLog {
            request_id: self.request_id,
            user_id: self.user_id,
            action: truncate_string(self.action),
            resource: self.resource.map(truncate_string),
            status: self.status.as_str().to_string(),
            ip_address: self.ip_address.map(truncate_string),
            user_agent: self.user_agent.map(truncate_string),
            metadata: sanitize_metadata(self.metadata),
        }
    }
}

pub fn sanitize_metadata(metadata: Value) -> Value {
    match sanitize_value(metadata) {
        Value::Object(object) => Value::Object(object),
        _ => json!({}),
    }
}

fn sanitize_value(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .filter_map(|(key, value)| {
                    if is_sensitive_key(&key) {
                        None
                    } else {
                        Some((key, sanitize_value(value)))
                    }
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(sanitize_value).collect()),
        Value::String(value) => Value::String(truncate_string(value)),
        other => other,
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let key = key.to_lowercase();
    SENSITIVE_KEY_PARTS
        .iter()
        .any(|sensitive| key.contains(sensitive))
}

fn add_request_metadata(request: &HttpRequest, metadata: Value) -> Value {
    let mut object = match metadata {
        Value::Object(object) => object,
        _ => Map::new(),
    };

    object.insert("method".to_string(), json!(request.method().as_str()));

    Value::Object(object)
}

fn request_id(request: &HttpRequest) -> Option<String> {
    request
        .extensions()
        .get::<RequestContext>()
        .map(|context| context.request_id.clone())
        .or_else(|| header_string(request, REQUEST_ID_HEADER))
        .map(truncate_string)
}

fn client_ip(request: &HttpRequest) -> Option<String> {
    request
        .connection_info()
        .realip_remote_addr()
        .map(normalize_ip)
        .or_else(|| request.peer_addr().map(peer_addr_without_port))
        .map(truncate_string)
}

fn normalize_ip(value: &str) -> String {
    value
        .parse::<SocketAddr>()
        .map(peer_addr_without_port)
        .unwrap_or_else(|_| value.to_string())
}

fn peer_addr_without_port(peer_addr: SocketAddr) -> String {
    peer_addr.ip().to_string()
}

fn user_agent(request: &HttpRequest) -> Option<String> {
    header_string(request, USER_AGENT)
}

fn header_string(request: &HttpRequest, name: HeaderName) -> Option<String> {
    request
        .headers()
        .get(name)?
        .to_str()
        .ok()
        .map(|value| value.chars().take(MAX_METADATA_STRING_LEN).collect())
}

fn truncate_string(value: String) -> String {
    value.chars().take(MAX_METADATA_STRING_LEN).collect()
}

#[cfg(test)]
mod tests {
    use super::sanitize_metadata;
    use serde_json::json;

    #[test]
    fn metadata_sanitizer_drops_sensitive_keys_recursively() {
        let metadata = sanitize_metadata(json!({
            "reason": "invalid credentials",
            "password": "secret",
            "refresh_token": "secret-refresh",
            "nested": {
                "authorization_header": "Bearer secret-access",
                "kept": "value"
            }
        }));

        assert_eq!(metadata["reason"], "invalid credentials");
        assert_eq!(metadata["nested"]["kept"], "value");
        assert!(metadata.get("password").is_none());
        assert!(metadata.get("refresh_token").is_none());
        assert!(
            metadata["nested"]
                .as_object()
                .expect("nested metadata should be object")
                .get("authorization_header")
                .is_none()
        );
    }
}
