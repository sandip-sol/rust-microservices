use actix_web::{
    HttpRequest, HttpResponse,
    http::{Method, StatusCode, header::HeaderName},
    web,
};
use bytes::Bytes;

use crate::{
    app::state::AppState,
    errors::AppError,
    middleware::auth::AuthenticatedUser,
    models::audit::AuditStatus,
    proxy::{
        headers::{gateway_headers, safe_forward_headers, should_skip_response_header},
        upstream::{MatchedUpstream, match_upstream},
    },
    services::audit_service::ACTION_PROXY_FAILURE,
};
use serde_json::json;

pub async fn forward(
    request: HttpRequest,
    body: Bytes,
    user: AuthenticatedUser,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    if body.len() > app_state.settings.proxy_max_body_bytes {
        return Err(AppError::BadRequest("request body too large".to_string()));
    }

    let upstream = match_upstream(request.path(), &app_state.settings)
        .ok_or_else(|| AppError::NotFound("route not found".to_string()))?;
    let response = match send_upstream_request(&request, body, &user, &app_state, &upstream).await {
        Ok(response) => response,
        Err(error) => {
            audit_proxy_failure(&request, &app_state, &user, &upstream, &error);
            return Err(error);
        }
    };

    match build_gateway_response(response).await {
        Ok(response) => Ok(response),
        Err(error) => {
            audit_proxy_failure(&request, &app_state, &user, &upstream, &error);
            Err(error)
        }
    }
}

async fn send_upstream_request(
    request: &HttpRequest,
    body: Bytes,
    user: &AuthenticatedUser,
    app_state: &AppState,
    upstream: &MatchedUpstream,
) -> Result<reqwest::Response, AppError> {
    let method = to_reqwest_method(request.method())?;
    let target_url =
        upstream.target_url((!request.query_string().is_empty()).then_some(request.query_string()));
    let mut builder = app_state.proxy_http_client.request(method, target_url);

    for (name, value) in safe_forward_headers(
        request.headers(),
        app_state.settings.proxy_forward_auth_header,
    ) {
        builder = builder.header(name, value);
    }

    for (name, value) in gateway_headers(request, user) {
        builder = builder.header(name, value);
    }

    builder.body(body).send().await.map_err(map_upstream_error)
}

async fn build_gateway_response(
    upstream_response: reqwest::Response,
) -> Result<HttpResponse, AppError> {
    let status = StatusCode::from_u16(upstream_response.status().as_u16())
        .unwrap_or(StatusCode::BAD_GATEWAY);
    let mut response = HttpResponse::build(status);

    for (name, value) in upstream_response.headers() {
        if should_skip_response_header(name.as_str()) {
            continue;
        }

        let Ok(name) = HeaderName::try_from(name.as_str()) else {
            continue;
        };
        let Ok(value) = value.to_str() else {
            continue;
        };

        response.insert_header((name, value));
    }

    let body = upstream_response
        .bytes()
        .await
        .map_err(map_upstream_error)?;
    Ok(response.body(body))
}

fn to_reqwest_method(method: &Method) -> Result<reqwest::Method, AppError> {
    reqwest::Method::from_bytes(method.as_str().as_bytes())
        .map_err(|_| AppError::BadRequest("unsupported HTTP method".to_string()))
}

pub fn map_upstream_error(error: reqwest::Error) -> AppError {
    if error.is_timeout() {
        AppError::GatewayTimeout("upstream request timed out".to_string())
    } else {
        AppError::BadGateway("upstream request failed".to_string())
    }
}

fn audit_proxy_failure(
    request: &HttpRequest,
    app_state: &AppState,
    user: &AuthenticatedUser,
    upstream: &MatchedUpstream,
    error: &AppError,
) {
    app_state.audit_service.record_request_event_detached(
        request,
        Some(user.user_id),
        ACTION_PROXY_FAILURE,
        AuditStatus::Failure,
        json!({
            "status_code": error_status_code(error),
            "error_kind": app_error_kind(error),
            "upstream_service": upstream.service.name(),
            "upstream_path": upstream.path,
        }),
    );
}

fn error_status_code(error: &AppError) -> u16 {
    use actix_web::ResponseError;

    error.status_code().as_u16()
}

fn app_error_kind(error: &AppError) -> &'static str {
    match error {
        AppError::BadGateway(_) => "bad_gateway",
        AppError::GatewayTimeout(_) => "gateway_timeout",
        AppError::BadRequest(_) => "bad_request",
        AppError::Unauthorized(_) => "unauthorized",
        AppError::Forbidden(_) => "forbidden",
        AppError::NotFound(_) => "not_found",
        AppError::Conflict(_) => "conflict",
        AppError::RateLimitExceeded(_) => "rate_limit_exceeded",
        AppError::Database => "database",
        AppError::PasswordHash => "password_hash",
        AppError::TokenCreation => "token_creation",
        AppError::Internal => "internal",
    }
}

#[cfg(test)]
mod tests {
    use super::map_upstream_error;
    use crate::errors::AppError;
    use actix_web::{ResponseError, http::StatusCode};

    #[test]
    fn gateway_errors_use_expected_status_codes() {
        let bad_gateway = AppError::BadGateway("upstream request failed".to_string());
        let timeout = AppError::GatewayTimeout("upstream request timed out".to_string());

        assert_eq!(bad_gateway.status_code(), StatusCode::BAD_GATEWAY);
        assert_eq!(timeout.status_code(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[test]
    fn non_timeout_reqwest_errors_map_to_bad_gateway() {
        let error = reqwest::Client::new()
            .get("not a valid URL")
            .build()
            .expect_err("invalid URL should fail to build");

        assert!(matches!(map_upstream_error(error), AppError::BadGateway(_)));
    }
}
