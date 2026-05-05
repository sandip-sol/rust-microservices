use actix_web::{
    HttpMessage, HttpRequest,
    http::header::{AUTHORIZATION, CONNECTION, CONTENT_LENGTH, COOKIE, HOST, HeaderMap, HeaderName},
};

use crate::middleware::{
    auth::AuthenticatedUser, request_context::RequestContext, request_id::REQUEST_ID_HEADER,
};

pub const USER_ID_HEADER: HeaderName = HeaderName::from_static("x-user-id");
pub const USER_EMAIL_HEADER: HeaderName = HeaderName::from_static("x-user-email");
pub const USER_ROLE_HEADER: HeaderName = HeaderName::from_static("x-user-role");

const HOP_BY_HOP_HEADERS: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

pub fn safe_forward_headers(headers: &HeaderMap, forward_auth_header: bool) -> Vec<(&str, &str)> {
    let connection_tokens = connection_tokens(headers);

    headers
        .iter()
        .filter_map(|(name, value)| {
            if should_skip_request_header(name, forward_auth_header)
                || is_connection_token(name, &connection_tokens)
            {
                return None;
            }

            value.to_str().ok().map(|value| (name.as_str(), value))
        })
        .collect()
}

pub fn gateway_headers(
    request: &HttpRequest,
    user: &AuthenticatedUser,
) -> Vec<(&'static str, String)> {
    vec![
        ("x-request-id", request_id(request)),
        ("x-user-id", user.user_id.to_string()),
        ("x-user-email", user.email().to_string()),
        ("x-user-role", user.role_name().to_string()),
    ]
}

pub fn is_hop_by_hop_header(name: &HeaderName) -> bool {
    HOP_BY_HOP_HEADERS
        .iter()
        .any(|header| name.as_str().eq_ignore_ascii_case(header))
}

pub fn should_skip_response_header(name: &str) -> bool {
    name.eq_ignore_ascii_case(CONTENT_LENGTH.as_str())
        || HOP_BY_HOP_HEADERS
            .iter()
            .any(|header| name.eq_ignore_ascii_case(header))
}

fn should_skip_request_header(name: &HeaderName, forward_auth_header: bool) -> bool {
    is_hop_by_hop_header(name)
        || name == HOST
        || name == CONTENT_LENGTH
        || name == USER_ID_HEADER
        || name == USER_EMAIL_HEADER
        || name == USER_ROLE_HEADER
        || name == REQUEST_ID_HEADER
        || name == COOKIE
        || (!forward_auth_header && name == AUTHORIZATION)
}

fn connection_tokens(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(CONNECTION)
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
        .collect()
}

fn is_connection_token(name: &HeaderName, connection_tokens: &[String]) -> bool {
    connection_tokens
        .iter()
        .any(|token| name.as_str().eq_ignore_ascii_case(token))
}

fn request_id(request: &HttpRequest) -> String {
    request
        .extensions()
        .get::<RequestContext>()
        .map(|context| context.request_id.clone())
        .or_else(|| {
            request
                .headers()
                .get(REQUEST_ID_HEADER)
                .and_then(|value| value.to_str().ok())
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

#[cfg(test)]
mod tests {
    use super::{USER_EMAIL_HEADER, USER_ID_HEADER, USER_ROLE_HEADER, safe_forward_headers};
    use crate::middleware::request_id::REQUEST_ID_HEADER;
    use actix_web::http::header::{
        AUTHORIZATION, CONNECTION, CONTENT_TYPE, COOKIE, HeaderMap, HeaderName,
    };

    #[test]
    fn forwards_safe_headers_and_strips_hop_by_hop_identity_and_auth_by_default() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            "application/json".parse().expect("valid header"),
        );
        headers.insert(
            AUTHORIZATION,
            "Bearer raw-token".parse().expect("valid header"),
        );
        headers.insert(
            CONNECTION,
            "keep-alive, x-extra-hop".parse().expect("valid header"),
        );
        headers.insert(
            HeaderName::from_static("x-extra-hop"),
            "drop-me".parse().expect("valid header"),
        );
        headers.insert(COOKIE, "session=secret".parse().expect("valid header"));
        headers.insert(USER_ID_HEADER, "client-user".parse().expect("valid header"));
        headers.insert(
            USER_EMAIL_HEADER,
            "client@example.com".parse().expect("valid header"),
        );
        headers.insert(USER_ROLE_HEADER, "admin".parse().expect("valid header"));
        headers.insert(
            REQUEST_ID_HEADER,
            "client-request".parse().expect("valid header"),
        );

        let forwarded = safe_forward_headers(&headers, false);

        assert_eq!(forwarded, vec![("content-type", "application/json")]);
    }

    #[test]
    fn can_forward_authorization_when_explicitly_enabled() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            "Bearer raw-token".parse().expect("valid header"),
        );

        let forwarded = safe_forward_headers(&headers, true);

        assert_eq!(forwarded, vec![("authorization", "Bearer raw-token")]);
    }
}
