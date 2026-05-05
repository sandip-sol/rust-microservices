use crate::config::settings::Settings;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamService {
    User,
    Payment,
}

impl UpstreamService {
    pub fn name(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Payment => "payment",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedUpstream {
    pub service: UpstreamService,
    pub base_url: String,
    pub path: String,
}

impl MatchedUpstream {
    pub fn target_url(&self, query: Option<&str>) -> String {
        let base_url = self.base_url.trim_end_matches('/');
        match query.filter(|value| !value.is_empty()) {
            Some(query) => format!("{base_url}{}?{query}", self.path),
            None => format!("{base_url}{}", self.path),
        }
    }
}

pub fn match_upstream(path: &str, settings: &Settings) -> Option<MatchedUpstream> {
    if is_reserved_gateway_path(path) {
        return None;
    }

    if matches_prefix(path, "/users") {
        return Some(MatchedUpstream {
            service: UpstreamService::User,
            base_url: settings.user_service_url.clone(),
            path: normalized_path(path),
        });
    }

    if matches_prefix(path, "/payments") {
        return Some(MatchedUpstream {
            service: UpstreamService::Payment,
            base_url: settings.payment_service_url.clone(),
            path: normalized_path(path),
        });
    }

    None
}

fn is_reserved_gateway_path(path: &str) -> bool {
    path == "/health" || path == "/auth" || path.starts_with("/auth/")
}

fn matches_prefix(path: &str, prefix: &str) -> bool {
    path == prefix || path.starts_with(&format!("{prefix}/"))
}

fn normalized_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

#[cfg(test)]
mod tests {
    use super::{UpstreamService, match_upstream};
    use crate::config::settings::Settings;

    fn settings() -> Settings {
        Settings {
            app_host: "127.0.0.1".to_string(),
            app_port: 8080,
            database_url: "postgres://postgres:postgres@localhost/sentinel_test".to_string(),
            redis_url: "redis://127.0.0.1/".to_string(),
            jwt_access_secret: "test-access-secret".to_string(),
            jwt_refresh_secret: "test-refresh-secret".to_string(),
            access_token_ttl_minutes: 15,
            refresh_token_ttl_days: 7,
            user_service_url: "http://user-service.local".to_string(),
            payment_service_url: "http://payment-service.local/".to_string(),
            proxy_timeout_seconds: 10,
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

    #[test]
    fn matches_configured_user_and_payment_routes() {
        let settings = settings();

        let users = match_upstream("/users/123/profile", &settings)
            .expect("users route should match user service");
        assert_eq!(users.service, UpstreamService::User);
        assert_eq!(
            users.target_url(Some("expand=roles")),
            "http://user-service.local/users/123/profile?expand=roles"
        );

        let payments = match_upstream("/payments", &settings).expect("payments route should match");
        assert_eq!(payments.service, UpstreamService::Payment);
        assert_eq!(
            payments.target_url(None),
            "http://payment-service.local/payments"
        );
    }

    #[test]
    fn does_not_match_gateway_reserved_or_similar_prefix_paths() {
        let settings = settings();

        assert!(match_upstream("/auth/login", &settings).is_none());
        assert!(match_upstream("/health", &settings).is_none());
        assert!(match_upstream("/users-and-groups", &settings).is_none());
        assert!(match_upstream("/payment-methods", &settings).is_none());
    }
}
