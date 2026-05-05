use redis::Client;

pub fn init_redis_client(redis_url: &str) -> Result<Client, redis::RedisError> {
    Client::open(redis_url)
}