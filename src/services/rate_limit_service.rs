use std::time::SystemTime;

use sha2::{Digest, Sha256};

use crate::{
    cache::rate_limit_store::RedisRateLimitStore,
    config::settings::Settings,
    models::rate_limit::{RateLimitDecision, RateLimitPolicy, RateLimitSubject},
};

#[derive(Debug, Clone)]
pub struct RateLimitService {
    settings: Settings,
    store: RedisRateLimitStore,
}

impl RateLimitService {
    pub fn new(settings: Settings, store: RedisRateLimitStore) -> Self {
        Self { settings, store }
    }

    pub async fn check(
        &self,
        policy: RateLimitPolicy,
        subject: &RateLimitSubject,
    ) -> Result<RateLimitDecision, redis::RedisError> {
        let limit = self.limit_for(policy);
        let key = build_rate_limit_key(&self.settings.rate_limit_redis_prefix, policy, subject);
        let counter = self
            .store
            .increment_fixed_window(&key, self.settings.rate_limit_window_seconds)
            .await?;

        Ok(RateLimitDecision::from_counter(
            counter,
            limit,
            self.settings.rate_limit_window_seconds,
            SystemTime::now(),
        ))
    }

    fn limit_for(&self, policy: RateLimitPolicy) -> u32 {
        match policy {
            RateLimitPolicy::Anonymous => self.settings.rate_limit_anon_per_minute,
            RateLimitPolicy::Authenticated => self.settings.rate_limit_auth_per_minute,
            RateLimitPolicy::AuthEndpoint => self.settings.rate_limit_auth_endpoint_per_minute,
        }
    }
}

pub fn build_rate_limit_key(
    prefix: &str,
    policy: RateLimitPolicy,
    subject: &RateLimitSubject,
) -> String {
    format!(
        "{}:{}:{}:{}",
        sanitize_rate_limit_prefix(prefix),
        policy.key_segment(),
        subject.key_segment(),
        hash_identifier(subject.identifier())
    )
}

pub fn sanitize_rate_limit_prefix(prefix: &str) -> String {
    prefix
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | ':'))
        .collect::<String>()
        .trim_matches(':')
        .to_string()
}

fn hash_identifier(identifier: &str) -> String {
    let digest = Sha256::digest(identifier.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::build_rate_limit_key;
    use crate::models::rate_limit::{RateLimitPolicy, RateLimitSubject};

    #[test]
    fn key_builder_includes_policy_and_subject_without_raw_identifier() {
        let key = build_rate_limit_key(
            "rate limit!",
            RateLimitPolicy::Anonymous,
            &RateLimitSubject::Ip("203.0.113.10".to_string()),
        );

        assert!(key.starts_with("ratelimit:anon:ip:"));
        assert!(!key.contains("203.0.113.10"));
    }

    #[test]
    fn key_builder_separates_authenticated_and_auth_endpoint_keys() {
        let subject = RateLimitSubject::User("user-1".to_string());

        let api_key = build_rate_limit_key("rl", RateLimitPolicy::Authenticated, &subject);
        let auth_endpoint_key = build_rate_limit_key("rl", RateLimitPolicy::AuthEndpoint, &subject);

        assert_ne!(api_key, auth_endpoint_key);
        assert!(api_key.starts_with("rl:auth:user:"));
        assert!(auth_endpoint_key.starts_with("rl:auth_endpoint:user:"));
    }
}
