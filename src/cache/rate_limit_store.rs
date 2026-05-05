use redis::{Client as RedisClient, RedisResult};

use crate::models::rate_limit::FixedWindowCounter;

const FIXED_WINDOW_SCRIPT: &str = r#"
local current = redis.call("INCR", KEYS[1])
if current == 1 then
  redis.call("EXPIRE", KEYS[1], ARGV[1])
end
local ttl = redis.call("TTL", KEYS[1])
return { current, ttl }
"#;

#[derive(Debug, Clone)]
pub struct RedisRateLimitStore {
    client: RedisClient,
}

impl RedisRateLimitStore {
    pub fn new(client: RedisClient) -> Self {
        Self { client }
    }

    pub async fn increment_fixed_window(
        &self,
        key: &str,
        window_seconds: u64,
    ) -> RedisResult<FixedWindowCounter> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let script = redis::Script::new(FIXED_WINDOW_SCRIPT);
        let (count, ttl): (u64, i64) = script
            .key(key)
            .arg(window_seconds)
            .invoke_async(&mut connection)
            .await?;

        Ok(FixedWindowCounter {
            count,
            ttl_seconds: ttl.max(0) as u64,
        })
    }
}
