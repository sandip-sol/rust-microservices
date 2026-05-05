use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::AppError;

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ValidatedRegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ValidatedLoginRequest {
    pub email: String,
    pub password: String,
}

impl RegisterRequest {
    pub fn validate(self) -> Result<ValidatedRegisterRequest, AppError> {
        let email = normalize_email(&self.email)?;
        let password = self.password;

        if password.trim().is_empty() {
            return Err(AppError::BadRequest("password is required".to_string()));
        }

        if password.len() < 8 {
            return Err(AppError::BadRequest(
                "password must be at least 8 characters".to_string(),
            ));
        }

        if password.len() > 128 {
            return Err(AppError::BadRequest(
                "password must be 128 characters or fewer".to_string(),
            ));
        }

        Ok(ValidatedRegisterRequest { email, password })
    }
}

impl LoginRequest {
    pub fn validate(self) -> Result<ValidatedLoginRequest, AppError> {
        let email = normalize_email(&self.email)?;

        if self.password.trim().is_empty() {
            return Err(AppError::BadRequest("password is required".to_string()));
        }

        Ok(ValidatedLoginRequest {
            email,
            password: self.password,
        })
    }
}

fn normalize_email(email: &str) -> Result<String, AppError> {
    let email = email.trim().to_lowercase();

    if email.is_empty() {
        return Err(AppError::BadRequest("email is required".to_string()));
    }

    if email.len() > 254 || !looks_like_email(&email) {
        return Err(AppError::BadRequest(
            "email must be a valid email address".to_string(),
        ));
    }

    Ok(email)
}

fn looks_like_email(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };

    !local.is_empty()
        && !domain.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !email.chars().any(char::is_whitespace)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: Uuid,
    pub email: String,
    pub role: String,
    pub exp: usize,
    pub iat: usize,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub user: crate::models::user::UserResponse,
}

#[cfg(test)]
mod tests {
    use super::{LoginRequest, RegisterRequest};
    use crate::errors::AppError;

    #[test]
    fn register_validation_normalizes_email() {
        let validated = RegisterRequest {
            email: "  PERSON@Example.COM ".to_string(),
            password: "correct horse".to_string(),
        }
        .validate()
        .expect("request should validate");

        assert_eq!(validated.email, "person@example.com");
        assert_eq!(validated.password, "correct horse");
    }

    #[test]
    fn register_validation_rejects_short_password() {
        let error = RegisterRequest {
            email: "person@example.com".to_string(),
            password: "short".to_string(),
        }
        .validate()
        .expect_err("short password should fail");

        assert!(matches!(error, AppError::BadRequest(_)));
    }

    #[test]
    fn login_validation_rejects_invalid_email() {
        let error = LoginRequest {
            email: "not-an-email".to_string(),
            password: "password".to_string(),
        }
        .validate()
        .expect_err("invalid email should fail");

        assert!(matches!(error, AppError::BadRequest(_)));
    }
}
