use redis::Client as RedisClient;
use sqlx::PgPool;

use crate::{
    config::settings::Settings,
    repositories::{
        audit_repository::AuditRepository, refresh_token_repository::RefreshTokenRepository,
        user_repository::UserRepository,
    },
    services::{audit_service::AuditService, auth_service::AuthService},
};

#[derive(Clone)]
pub struct AppState {
    pub settings: Settings,
    pub db_pool: PgPool,
    pub redis_client: RedisClient,
    pub user_repository: UserRepository,
    pub refresh_token_repository: RefreshTokenRepository,
    pub audit_repository: AuditRepository,
    pub auth_service: AuthService,
    pub audit_service: AuditService,
}
