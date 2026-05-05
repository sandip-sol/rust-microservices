use std::{
    future::{Future, Ready, ready},
    net::SocketAddr,
    pin::Pin,
    rc::Rc,
};

use actix_web::{
    Error, HttpResponse, ResponseError,
    body::{EitherBody, MessageBody},
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    http::header::{HeaderName, HeaderValue, RETRY_AFTER},
    web,
};

use crate::{
    app::state::AppState,
    auth::jwt::validate_access_token,
    cache::rate_limit_store::RedisRateLimitStore,
    errors::AppError,
    models::audit::AuditStatus,
    models::rate_limit::{RateLimitDecision, RateLimitPolicy, RateLimitSubject},
    services::audit_service::{ACTION_RATE_LIMIT_EXCEEDED, AuditEvent},
    services::rate_limit_service::RateLimitService,
};
use serde_json::json;
use uuid::Uuid;

const RATE_LIMIT_LIMIT: HeaderName = HeaderName::from_static("x-ratelimit-limit");
const RATE_LIMIT_REMAINING: HeaderName = HeaderName::from_static("x-ratelimit-remaining");
const RATE_LIMIT_RESET: HeaderName = HeaderName::from_static("x-ratelimit-reset");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitScope {
    Automatic,
    Api,
    AuthEndpoint,
}

#[derive(Debug, Clone)]
pub struct RateLimit {
    scope: RateLimitScope,
}

impl RateLimit {
    pub fn automatic() -> Self {
        Self {
            scope: RateLimitScope::Automatic,
        }
    }

    pub fn api() -> Self {
        Self {
            scope: RateLimitScope::Api,
        }
    }

    pub fn auth_endpoint() -> Self {
        Self {
            scope: RateLimitScope::AuthEndpoint,
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RateLimit
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = RateLimitMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RateLimitMiddleware {
            service: Rc::new(service),
            scope: self.scope,
        }))
    }
}

pub struct RateLimitMiddleware<S> {
    service: Rc<S>,
    scope: RateLimitScope,
}

impl<S, B> Service<ServiceRequest> for RateLimitMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, request: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let scope = self.scope;

        Box::pin(async move {
            let Some(app_state) = request.app_data::<web::Data<AppState>>().cloned() else {
                return Err(AppError::Internal.into());
            };

            if !app_state.settings.rate_limit_enabled || should_skip_rate_limit(&request, scope) {
                return service
                    .call(request)
                    .await
                    .map(ServiceResponse::map_into_left_body);
            }

            let (policy, subject) = classify_request(&request, scope, &app_state);
            let rate_limit_service = RateLimitService::new(
                app_state.settings.clone(),
                RedisRateLimitStore::new(app_state.redis_client.clone()),
            );
            let decision = rate_limit_service
                .check(policy, &subject)
                .await
                .map_err(|error| {
                    tracing::error!(error = %error, "Redis rate limit check failed");
                    AppError::Internal
                })?;

            if !decision.allowed {
                app_state
                    .audit_service
                    .record_safely(AuditEvent::from_request(
                        request.request(),
                        audit_user_id(&subject),
                        ACTION_RATE_LIMIT_EXCEEDED,
                        AuditStatus::Denied,
                        json!({
                            "policy": policy.key_segment(),
                            "subject_type": subject.key_segment(),
                            "limit": decision.limit,
                            "remaining": decision.remaining,
                            "reset_after_seconds": decision.reset_after.as_secs(),
                        }),
                    ))
                    .await;
                let response = too_many_requests_response(&decision);
                return Ok(request.into_response(response).map_into_right_body());
            }

            let mut response = service.call(request).await?.map_into_left_body();
            insert_rate_limit_headers(response.headers_mut(), &decision, false);
            Ok(response)
        })
    }
}

fn should_skip_rate_limit(request: &ServiceRequest, scope: RateLimitScope) -> bool {
    scope == RateLimitScope::Automatic && request.path() == "/health"
}

fn classify_request(
    request: &ServiceRequest,
    scope: RateLimitScope,
    app_state: &AppState,
) -> (RateLimitPolicy, RateLimitSubject) {
    let subject = authenticated_subject(request, app_state)
        .unwrap_or_else(|| RateLimitSubject::Ip(client_ip(request)));

    let policy = match scope {
        RateLimitScope::AuthEndpoint => RateLimitPolicy::AuthEndpoint,
        RateLimitScope::Api => match &subject {
            RateLimitSubject::User(_) => RateLimitPolicy::Authenticated,
            RateLimitSubject::Ip(_) => RateLimitPolicy::Anonymous,
        },
        RateLimitScope::Automatic if is_auth_endpoint(request.path()) => {
            RateLimitPolicy::AuthEndpoint
        }
        RateLimitScope::Automatic => match &subject {
            RateLimitSubject::User(_) => RateLimitPolicy::Authenticated,
            RateLimitSubject::Ip(_) => RateLimitPolicy::Anonymous,
        },
    };

    (policy, subject)
}

fn is_auth_endpoint(path: &str) -> bool {
    path == "/auth" || path.starts_with("/auth/")
}

fn audit_user_id(subject: &RateLimitSubject) -> Option<Uuid> {
    match subject {
        RateLimitSubject::User(user_id) => Uuid::parse_str(user_id).ok(),
        RateLimitSubject::Ip(_) => None,
    }
}

fn authenticated_subject(
    request: &ServiceRequest,
    app_state: &AppState,
) -> Option<RateLimitSubject> {
    let token = bearer_token(request)?;
    let claims = validate_access_token(token, &app_state.settings).ok()?;
    Some(RateLimitSubject::User(claims.sub))
}

fn bearer_token(request: &ServiceRequest) -> Option<&str> {
    request
        .headers()
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .filter(|token| !token.trim().is_empty() && token.trim() == *token)
}

fn client_ip(request: &ServiceRequest) -> String {
    request
        .connection_info()
        .realip_remote_addr()
        .map(normalize_ip)
        .or_else(|| request.peer_addr().map(peer_addr_without_port))
        .unwrap_or_else(|| "unknown".to_string())
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

fn too_many_requests_response(decision: &RateLimitDecision) -> HttpResponse {
    let mut response =
        AppError::RateLimitExceeded("rate limit exceeded".to_string()).error_response();
    insert_rate_limit_headers(response.headers_mut(), decision, true);
    response
}

fn insert_rate_limit_headers(
    headers: &mut actix_web::http::header::HeaderMap,
    decision: &RateLimitDecision,
    include_retry_after: bool,
) {
    insert_header(headers, RATE_LIMIT_LIMIT, decision.limit);
    insert_header(headers, RATE_LIMIT_REMAINING, decision.remaining);
    insert_header(headers, RATE_LIMIT_RESET, decision.reset_epoch_seconds);

    if include_retry_after {
        insert_header(headers, RETRY_AFTER, decision.reset_after.as_secs());
    }
}

fn insert_header<T: ToString>(
    headers: &mut actix_web::http::header::HeaderMap,
    name: HeaderName,
    value: T,
) {
    if let Ok(value) = HeaderValue::from_str(&value.to_string()) {
        headers.insert(name, value);
    }
}

#[cfg(test)]
mod tests {
    use super::{RateLimitScope, classify_request, is_auth_endpoint};
    use crate::{
        app::state::AppState,
        config::settings::Settings,
        models::rate_limit::{RateLimitPolicy, RateLimitSubject},
        repositories::{
            audit_repository::AuditRepository, refresh_token_repository::RefreshTokenRepository,
            user_repository::UserRepository,
        },
        services::{audit_service::AuditService, auth_service::AuthService},
    };
    use actix_web::test as actix_test;
    use redis::Client as RedisClient;
    use sqlx::postgres::PgPoolOptions;

    fn app_state() -> AppState {
        let settings = Settings {
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
        };
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

    #[test]
    fn auth_scope_matches_auth_paths_only() {
        assert!(is_auth_endpoint("/auth/login"));
        assert!(is_auth_endpoint("/auth/me"));
        assert!(!is_auth_endpoint("/health"));
        assert!(!is_auth_endpoint("/api/authors"));
    }

    #[actix_web::test]
    async fn automatic_scope_classifies_anonymous_auth_endpoint_as_strict() {
        let request = actix_test::TestRequest::post()
            .uri("/auth/login")
            .peer_addr("203.0.113.1:5000".parse().expect("valid socket address"))
            .to_srv_request();
        let state = app_state();

        let (policy, subject) = classify_request(&request, RateLimitScope::Automatic, &state);

        assert_eq!(policy, RateLimitPolicy::AuthEndpoint);
        assert_eq!(subject, RateLimitSubject::Ip("203.0.113.1".to_string()));
    }
}
