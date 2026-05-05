use crate::{
    auth::{
        jwt::generate_access_token,
        password::{hash_password, verify_password},
    },
    config::settings::Settings,
    models::{
        auth::{AuthResponse, LoginRequest, RegisterRequest},
        user::UserResponse,
    },
    repositories::user_repository::UserRepository,
};

#[derive(Clone)]
pub struct AuthService {
    user_repository: UserRepository,
    settings: Settings,
}

impl AuthService {
    pub fn new(user_repository: UserRepository, settings: Settings) -> Self {
        Self {
            user_repository,
            settings,
        }
    }

    pub async fn register(&self, payload: RegisterRequest) -> Result<UserResponse, String> {
        let email = payload.email.trim().to_lowercase();

        if email.is_empty() || payload.password.trim().is_empty() {
            return Err("email and password are required".to_string());
        }

        if payload.password.len() < 8 {
            return Err("password must be at least 8 characters".to_string());
        }

        let existing = self
            .user_repository
            .find_by_email(&email)
            .await
            .map_err(|_| "database error while checking existing user".to_string())?;

        if existing.is_some() {
            return Err("user already exists".to_string());
        }

        let password_hash =
            hash_password(&payload.password).map_err(|_| "failed to hash password".to_string())?;

        let user = self
            .user_repository
            .create_user(&email, &password_hash, "user")
            .await
            .map_err(|_| "failed to create user".to_string())?;

        Ok(user.into())
    }

    pub async fn login(&self, payload: LoginRequest) -> Result<AuthResponse, String> {
        let email = payload.email.trim().to_lowercase();

        let user = self
            .user_repository
            .find_by_email(&email)
            .await
            .map_err(|_| "database error while loading user".to_string())?
            .ok_or_else(|| "invalid credentials".to_string())?;

        let valid = verify_password(&payload.password, &user.password_hash)
            .map_err(|_| "failed to verify password".to_string())?;

        if !valid {
            return Err("invalid credentials".to_string());
        }

        let (access_token, expires_in) =
            generate_access_token(&user, &self.settings).map_err(|_| "failed to issue token".to_string())?;

        Ok(AuthResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in,
            user: user.into(),
        })
    }
}