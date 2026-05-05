use redis::Client as RedisClient;
use sqlx::PgPool;

use crate::{
    config::settings::Settings,
    repositories::{
        refresh_token_repository::RefreshTokenRepository, user_repository::UserRepository,
    },
    services::auth_service::AuthService,
};

#[derive(Clone)]
pub struct AppState {
    pub settings: Settings,
    pub db_pool: PgPool,
    pub redis_client: RedisClient,
    pub user_repository: UserRepository,
    pub refresh_token_repository: RefreshTokenRepository,
    pub auth_service: AuthService,
}
