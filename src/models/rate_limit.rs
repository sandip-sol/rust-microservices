use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitPolicy {
    Anonymous,
    Authenticated,
    AuthEndpoint,
}

impl RateLimitPolicy {
    pub fn key_segment(self) -> &'static str {
        match self {
            Self::Anonymous => "anon",
            Self::Authenticated => "auth",
            Self::AuthEndpoint => "auth_endpoint",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitSubject {
    Ip(String),
    User(String),
}

impl RateLimitSubject {
    pub fn key_segment(&self) -> &'static str {
        match self {
            Self::Ip(_) => "ip",
            Self::User(_) => "user",
        }
    }

    pub fn identifier(&self) -> &str {
        match self {
            Self::Ip(identifier) | Self::User(identifier) => identifier,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedWindowCounter {
    pub count: u64,
    pub ttl_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitDecision {
    pub allowed: bool,
    pub limit: u32,
    pub remaining: u32,
    pub reset_after: Duration,
    pub reset_epoch_seconds: u64,
}

impl RateLimitDecision {
    pub fn from_counter(
        counter: FixedWindowCounter,
        limit: u32,
        window_seconds: u64,
        now: SystemTime,
    ) -> Self {
        let ttl_seconds = if counter.ttl_seconds == 0 {
            window_seconds
        } else {
            counter.ttl_seconds
        };
        let remaining = limit.saturating_sub(counter.count as u32);
        let reset_epoch_seconds = now
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_add(ttl_seconds);

        Self {
            allowed: counter.count <= limit as u64,
            limit,
            remaining,
            reset_after: Duration::from_secs(ttl_seconds),
            reset_epoch_seconds,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FixedWindowCounter, RateLimitDecision};
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn decision_allows_requests_at_the_limit() {
        let decision = RateLimitDecision::from_counter(
            FixedWindowCounter {
                count: 10,
                ttl_seconds: 42,
            },
            10,
            60,
            UNIX_EPOCH + Duration::from_secs(1_000),
        );

        assert!(decision.allowed);
        assert_eq!(decision.remaining, 0);
        assert_eq!(decision.reset_after, Duration::from_secs(42));
        assert_eq!(decision.reset_epoch_seconds, 1_042);
    }

    #[test]
    fn decision_rejects_requests_over_the_limit() {
        let decision = RateLimitDecision::from_counter(
            FixedWindowCounter {
                count: 11,
                ttl_seconds: 30,
            },
            10,
            60,
            UNIX_EPOCH,
        );

        assert!(!decision.allowed);
        assert_eq!(decision.remaining, 0);
    }
}
