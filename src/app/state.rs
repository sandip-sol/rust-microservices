use redis::Client as RedisClient;
use sqlx::PgPool;

use crate::{
    config::settings::Settings,
    repositories::user_repository::UserRepository,
    services::auth_service::AuthService,
};

#[derive(Clone)]
pub struct AppState {
    pub settings: Settings,
    pub db_pool: PgPool,
    pub redis_client: RedisClient,
    pub user_repository: UserRepository,
    pub auth_service: AuthService,
}