use crate::{
    auth::{
        jwt::{generate_access_token, validate_access_token},
        password::{hash_password, verify_password},
        refresh_token::{generate_refresh_token, hash_refresh_token},
    },
    config::settings::Settings,
    errors::AppError,
    models::{
        auth::{
            AuthResponse, LoginRequest, LogoutRequest, RefreshRequest, RegisterRequest,
            ValidatedLoginRequest, ValidatedRefreshTokenRequest, ValidatedRegisterRequest,
        },
        user::{User, UserResponse},
    },
    repositories::{
        refresh_token_repository::RefreshTokenRepository, user_repository::UserRepository,
    },
};
use chrono::{Duration, Utc};

#[derive(Clone)]
pub struct AuthService {
    user_repository: UserRepository,
    refresh_token_repository: RefreshTokenRepository,
    settings: Settings,
}

impl AuthService {
    pub fn new(
        user_repository: UserRepository,
        refresh_token_repository: RefreshTokenRepository,
        settings: Settings,
    ) -> Self {
        Self {
            user_repository,
            refresh_token_repository,
            settings,
        }
    }

    pub async fn register(&self, payload: RegisterRequest) -> Result<UserResponse, AppError> {
        let ValidatedRegisterRequest { email, password } = payload.validate()?;

        let existing = self
            .user_repository
            .find_by_email(&email)
            .await
            .map_err(|_| AppError::Database)?;

        if existing.is_some() {
            return Err(AppError::Conflict("user already exists".to_string()));
        }

        let password_hash = hash_password(&password).map_err(|_| AppError::PasswordHash)?;

        let user = self
            .user_repository
            .create_user(&email, &password_hash, "user")
            .await
            .map_err(map_create_user_error)?;

        Ok(user.into())
    }

    pub async fn login(&self, payload: LoginRequest) -> Result<AuthResponse, AppError> {
        let ValidatedLoginRequest { email, password } = payload.validate()?;

        let user = self
            .user_repository
            .find_by_email(&email)
            .await
            .map_err(|_| AppError::Database)?
            .ok_or_else(|| AppError::Unauthorized("invalid credentials".to_string()))?;

        let valid =
            verify_password(&password, &user.password_hash).map_err(|_| AppError::PasswordHash)?;

        if !valid {
            return Err(AppError::Unauthorized("invalid credentials".to_string()));
        }

        self.issue_auth_response(user).await
    }

    pub async fn refresh(&self, payload: RefreshRequest) -> Result<AuthResponse, AppError> {
        let ValidatedRefreshTokenRequest { refresh_token } = payload.validate()?;
        let token_hash = hash_refresh_token(&refresh_token, &self.settings.jwt_refresh_secret);

        let stored_token = self
            .refresh_token_repository
            .find_by_hash(&token_hash)
            .await
            .map_err(|_| AppError::Database)?
            .ok_or_else(invalid_refresh_token)?;

        if stored_token.revoked_at.is_some() {
            self.refresh_token_repository
                .revoke_all_for_user(stored_token.user_id)
                .await
                .map_err(|_| AppError::Database)?;
            return Err(invalid_refresh_token());
        }

        if !stored_token.is_active(Utc::now()) {
            self.refresh_token_repository
                .revoke(stored_token.id)
                .await
                .map_err(|_| AppError::Database)?;
            return Err(invalid_refresh_token());
        }

        let user = self
            .user_repository
            .find_by_id(stored_token.user_id)
            .await
            .map_err(|_| AppError::Database)?
            .ok_or_else(invalid_refresh_token)?;

        self.rotate_auth_response(user, stored_token.id).await
    }

    pub async fn logout(&self, payload: LogoutRequest) -> Result<(), AppError> {
        let ValidatedRefreshTokenRequest { refresh_token } = payload.validate()?;
        let token_hash = hash_refresh_token(&refresh_token, &self.settings.jwt_refresh_secret);

        self.refresh_token_repository
            .revoke_by_hash(&token_hash)
            .await
            .map_err(|_| AppError::Database)?;

        Ok(())
    }

    pub async fn current_user(&self, access_token: &str) -> Result<UserResponse, AppError> {
        let claims = validate_access_token(access_token, &self.settings)
            .map_err(|_| AppError::Unauthorized("invalid access token".to_string()))?;
        let user_id = claims
            .sub
            .parse()
            .map_err(|_| AppError::Unauthorized("invalid access token".to_string()))?;

        let user = self
            .user_repository
            .find_by_id(user_id)
            .await
            .map_err(|_| AppError::Database)?
            .ok_or_else(|| AppError::Unauthorized("invalid access token".to_string()))?;

        Ok(user.into())
    }

    async fn issue_auth_response(&self, user: User) -> Result<AuthResponse, AppError> {
        let (access_token, expires_in) =
            generate_access_token(&user, &self.settings).map_err(|_| AppError::TokenCreation)?;
        let refresh_token = generate_refresh_token();
        let refresh_token_hash =
            hash_refresh_token(&refresh_token, &self.settings.jwt_refresh_secret);
        let refresh_expires_at = Utc::now() + Duration::days(self.settings.refresh_token_ttl_days);

        self.refresh_token_repository
            .create(user.id, &refresh_token_hash, refresh_expires_at)
            .await
            .map_err(|_| AppError::Database)?;

        Ok(AuthResponse {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in,
            user: user.into(),
        })
    }

    async fn rotate_auth_response(
        &self,
        user: User,
        old_refresh_token_id: uuid::Uuid,
    ) -> Result<AuthResponse, AppError> {
        let (access_token, expires_in) =
            generate_access_token(&user, &self.settings).map_err(|_| AppError::TokenCreation)?;
        let refresh_token = generate_refresh_token();
        let refresh_token_hash =
            hash_refresh_token(&refresh_token, &self.settings.jwt_refresh_secret);
        let refresh_expires_at = Utc::now() + Duration::days(self.settings.refresh_token_ttl_days);

        self.refresh_token_repository
            .rotate(
                old_refresh_token_id,
                user.id,
                &refresh_token_hash,
                refresh_expires_at,
            )
            .await
            .map_err(|_| AppError::Database)?
            .ok_or_else(invalid_refresh_token)?;

        Ok(AuthResponse {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in,
            user: user.into(),
        })
    }
}

fn invalid_refresh_token() -> AppError {
    AppError::Unauthorized("invalid refresh token".to_string())
}

fn map_create_user_error(error: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(db_error) = &error
        && (db_error.constraint() == Some("users_email_key")
            || db_error.code().as_deref() == Some("23505"))
    {
        return AppError::Conflict("user already exists".to_string());
    }

    AppError::Database
}
