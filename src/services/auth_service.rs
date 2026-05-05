use crate::{
    auth::{
        jwt::generate_access_token,
        password::{hash_password, verify_password},
    },
    config::settings::Settings,
    errors::AppError,
    models::{
        auth::{
            AuthResponse, LoginRequest, RegisterRequest, ValidatedLoginRequest,
            ValidatedRegisterRequest,
        },
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

        let (access_token, expires_in) =
            generate_access_token(&user, &self.settings).map_err(|_| AppError::TokenCreation)?;

        Ok(AuthResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in,
            user: user.into(),
        })
    }
}

fn map_create_user_error(error: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(db_error) = &error {
        if db_error.constraint() == Some("users_email_key")
            || db_error.code().as_deref() == Some("23505")
        {
            return AppError::Conflict("user already exists".to_string());
        }
    }

    AppError::Database
}
