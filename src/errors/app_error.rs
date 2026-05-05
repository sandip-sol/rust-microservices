use actix_web::{HttpResponse, ResponseError, http::StatusCode, web};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: String,
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("database error")]
    Database,

    #[error("password hashing error")]
    PasswordHash,

    #[error("token generation error")]
    TokenCreation,

    #[error("internal server error")]
    Internal,
}

impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::Database => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::PasswordHash => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::TokenCreation => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(ErrorBody {
            error: self.client_message(),
        })
    }
}

impl AppError {
    fn client_message(&self) -> String {
        match self {
            AppError::BadRequest(message)
            | AppError::Unauthorized(message)
            | AppError::Forbidden(message)
            | AppError::NotFound(message)
            | AppError::Conflict(message) => message.clone(),
            AppError::Database
            | AppError::PasswordHash
            | AppError::TokenCreation
            | AppError::Internal => "internal server error".to_string(),
        }
    }
}

pub fn json_config() -> web::JsonConfig {
    web::JsonConfig::default()
        .error_handler(|_, _| AppError::BadRequest("invalid JSON request body".to_string()).into())
}
