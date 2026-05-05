use std::{
    future::{Future, Ready, ready},
    net::SocketAddr,
    pin::Pin,
    rc::Rc,
    time::Instant,
};

use actix_web::{
    Error, HttpMessage,
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    http::{StatusCode, header::USER_AGENT},
};

use crate::middleware::{auth::AuthenticatedUser, request_context::RequestContext};

#[derive(Debug, Clone, Default)]
pub struct RequestLogging;

impl RequestLogging {
    pub fn new() -> Self {
        Self
    }
}

impl<S, B> Transform<S, ServiceRequest> for RequestLogging
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = RequestLoggingMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequestLoggingMiddleware {
            service: Rc::new(service),
        }))
    }
}

pub struct RequestLoggingMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for RequestLoggingMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, request: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let fallback_started_at = Instant::now();
        let request_context = request.extensions().get::<RequestContext>().cloned();
        let request_id = request_context
            .as_ref()
            .map(|context| context.request_id.clone())
            .unwrap_or_else(|| "unknown".to_string());
        let started_at = request_context
            .as_ref()
            .map(|context| context.started_at)
            .unwrap_or(fallback_started_at);
        let method = request.method().to_string();
        let path = request.path().to_string();
        let client_ip = client_ip(&request);
        let user_agent = user_agent(&request);

        Box::pin(async move {
            match service.call(request).await {
                Ok(response) => {
                    let status = response.status();
                    let duration_ms = started_at.elapsed().as_millis();
                    let authenticated_user = response
                        .request()
                        .extensions()
                        .get::<AuthenticatedUser>()
                        .cloned();

                    log_request(
                        RequestLogMetadata {
                            request_id: &request_id,
                            method: &method,
                            path: &path,
                            status,
                            duration_ms,
                            client_ip: &client_ip,
                            user_agent: &user_agent,
                        },
                        authenticated_user.as_ref(),
                    );

                    Ok(response)
                }
                Err(error) => {
                    tracing::error!(
                        request_id = %request_id,
                        method = %method,
                        path = %path,
                        status_code = 500_u16,
                        duration_ms = started_at.elapsed().as_millis(),
                        client_ip = %client_ip,
                        user_agent = %user_agent,
                        "request failed"
                    );

                    Err(error)
                }
            }
        })
    }
}

struct RequestLogMetadata<'a> {
    request_id: &'a str,
    method: &'a str,
    path: &'a str,
    status: StatusCode,
    duration_ms: u128,
    client_ip: &'a str,
    user_agent: &'a str,
}

fn log_request(metadata: RequestLogMetadata<'_>, authenticated_user: Option<&AuthenticatedUser>) {
    if let Some(user) = authenticated_user {
        tracing::info!(
            request_id = %metadata.request_id,
            method = %metadata.method,
            path = %metadata.path,
            status_code = metadata.status.as_u16(),
            duration_ms = metadata.duration_ms,
            client_ip = %metadata.client_ip,
            user_agent = %metadata.user_agent,
            user_id = %user.user_id,
            user_email = %user.email(),
            user_role = %user.role_name(),
            "request completed"
        );
    } else {
        tracing::info!(
            request_id = %metadata.request_id,
            method = %metadata.method,
            path = %metadata.path,
            status_code = metadata.status.as_u16(),
            duration_ms = metadata.duration_ms,
            client_ip = %metadata.client_ip,
            user_agent = %metadata.user_agent,
            "request completed"
        );
    }
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

fn user_agent(request: &ServiceRequest) -> String {
    request
        .headers()
        .get(USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.chars().take(512).collect())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::RequestLogging;
    use crate::{
        app::state::AppState,
        auth::jwt::generate_access_token,
        config::settings::Settings,
        errors::json_config,
        middleware::{auth::AuthenticatedUser, request_id::RequestId},
        models::user::User,
        repositories::{
            refresh_token_repository::RefreshTokenRepository, user_repository::UserRepository,
        },
        services::auth_service::AuthService,
    };
    use actix_web::{App, HttpResponse, http::StatusCode, test, web};
    use chrono::Utc;
    use redis::Client as RedisClient;
    use sqlx::postgres::PgPoolOptions;
    use std::{
        io::{self, Write},
        sync::{Arc, Mutex},
    };
    use tracing_subscriber::fmt::MakeWriter;
    use uuid::Uuid;

    #[derive(Clone)]
    struct SharedWriter {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for SharedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.buffer
                .lock()
                .expect("log buffer should not be poisoned")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct SharedMakeWriter {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl<'a> MakeWriter<'a> for SharedMakeWriter {
        type Writer = SharedWriter;

        fn make_writer(&'a self) -> Self::Writer {
            SharedWriter {
                buffer: self.buffer.clone(),
            }
        }
    }

    fn capture_logs() -> (tracing::Dispatch, Arc<Mutex<Vec<u8>>>) {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::INFO)
            .with_writer(SharedMakeWriter {
                buffer: buffer.clone(),
            })
            .finish();

        (tracing::Dispatch::new(subscriber), buffer)
    }

    fn logs_from(buffer: &Arc<Mutex<Vec<u8>>>) -> String {
        let bytes = buffer
            .lock()
            .expect("log buffer should not be poisoned")
            .clone();
        String::from_utf8(bytes).expect("logs should be utf-8")
    }

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

    fn token_for_user(user: &User, settings: &Settings) -> String {
        generate_access_token(user, settings)
            .expect("test token should be generated")
            .0
    }

    async fn ok() -> HttpResponse {
        HttpResponse::Ok().finish()
    }

    async fn protected(user: AuthenticatedUser) -> HttpResponse {
        HttpResponse::Ok().json(serde_json::json!({
            "id": user.user_id,
            "email": user.email(),
            "role": user.role_name()
        }))
    }

    #[actix_web::test]
    async fn request_logging_records_safe_request_metadata() {
        let (dispatch, buffer) = capture_logs();
        let _guard = tracing::dispatcher::set_default(&dispatch);
        let app = test::init_service(
            App::new()
                .wrap(RequestLogging::new())
                .wrap(RequestId::new())
                .route("/ok", web::post().to(ok)),
        )
        .await;
        let request_id = Uuid::new_v4().to_string();

        let request = test::TestRequest::post()
            .uri("/ok?access_token=secret-query-token")
            .peer_addr("203.0.113.42:5000".parse().expect("valid socket address"))
            .insert_header(("x-request-id", request_id.as_str()))
            .insert_header(("authorization", "Bearer secret-access-token"))
            .insert_header(("user-agent", "Phase5Test/1.0"))
            .set_payload("password=secret-password&refresh_token=secret-refresh-token")
            .to_request();
        let response = test::call_service(&app, request).await;

        assert_eq!(response.status(), StatusCode::OK);
        let logs = logs_from(&buffer);
        assert!(logs.contains("request completed"));
        assert!(logs.contains(&format!("request_id={request_id}")));
        assert!(logs.contains("method=POST"));
        assert!(logs.contains("path=/ok"));
        assert!(logs.contains("status_code=200"));
        assert!(logs.contains("client_ip=203.0.113.42"));
        assert!(logs.contains("user_agent=Phase5Test/1.0"));
        assert!(!logs.contains("secret-query-token"));
        assert!(!logs.contains("secret-access-token"));
        assert!(!logs.contains("secret-password"));
        assert!(!logs.contains("secret-refresh-token"));
    }

    #[actix_web::test]
    async fn request_logging_includes_authenticated_user_fields_when_available() {
        let (dispatch, buffer) = capture_logs();
        let _guard = tracing::dispatcher::set_default(&dispatch);
        let app_state = test_app_state();
        let user = User {
            id: Uuid::new_v4(),
            email: "trace-user@example.com".to_string(),
            password_hash: "not-used".to_string(),
            role: "admin".to_string(),
            created_at: Utc::now(),
        };
        let token = token_for_user(&user, &app_state.settings);
        let app = test::init_service(
            App::new()
                .wrap(RequestLogging::new())
                .wrap(RequestId::new())
                .app_data(web::Data::new(app_state))
                .app_data(json_config())
                .route("/protected", web::get().to(protected)),
        )
        .await;

        let request = test::TestRequest::get()
            .uri("/protected")
            .insert_header(("authorization", format!("Bearer {token}")))
            .to_request();
        let response = test::call_service(&app, request).await;

        assert_eq!(response.status(), StatusCode::OK);
        let logs = logs_from(&buffer);
        assert!(logs.contains(&format!("user_id={}", user.id)));
        assert!(logs.contains("user_email=trace-user@example.com"));
        assert!(logs.contains("user_role=admin"));
        assert!(!logs.contains(&token));
    }
}
