use std::future::{Ready, ready};

use actix_web::{FromRequest, HttpMessage, HttpRequest, dev::Payload, web};
use serde::Serialize;
use uuid::Uuid;

use crate::{
    app::state::AppState,
    auth::{
        claims::{Claims, Role},
        jwt::validate_access_token,
    },
    errors::AppError,
};

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub claims: Claims,
    pub user_id: Uuid,
    pub role: Role,
}

#[derive(Debug, Serialize)]
pub struct AuthenticatedUserResponse {
    pub id: Uuid,
    pub email: String,
    pub role: String,
}

impl AuthenticatedUser {
    pub fn email(&self) -> &str {
        &self.claims.email
    }

    pub fn role_name(&self) -> &'static str {
        self.role.as_str()
    }

    pub fn require_role(&self, required: Role) -> Result<(), AppError> {
        if self.role.can_access(required) {
            Ok(())
        } else {
            Err(forbidden())
        }
    }

    pub fn into_response(self) -> AuthenticatedUserResponse {
        AuthenticatedUserResponse {
            id: self.user_id,
            email: self.claims.email,
            role: self.role.as_str().to_string(),
        }
    }

    fn from_claims(claims: Claims) -> Result<Self, AppError> {
        let user_id = claims.sub.parse().map_err(|_| invalid_access_token())?;
        let role = Role::parse(&claims.role).ok_or_else(invalid_access_token)?;

        Ok(Self {
            claims,
            user_id,
            role,
        })
    }
}

impl FromRequest for AuthenticatedUser {
    type Error = AppError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(request: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        ready(authenticate_request(request))
    }
}

#[derive(Debug, Clone)]
pub struct RequireUser(pub AuthenticatedUser);

#[derive(Debug, Clone)]
pub struct RequireAdmin(pub AuthenticatedUser);

#[derive(Debug, Clone)]
pub struct RequireService(pub AuthenticatedUser);

impl FromRequest for RequireUser {
    type Error = AppError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(request: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        ready(require_role(request, Role::User).map(Self))
    }
}

impl FromRequest for RequireAdmin {
    type Error = AppError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(request: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        ready(require_role(request, Role::Admin).map(Self))
    }
}

impl FromRequest for RequireService {
    type Error = AppError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(request: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        ready(require_role(request, Role::Service).map(Self))
    }
}

fn require_role(request: &HttpRequest, required: Role) -> Result<AuthenticatedUser, AppError> {
    let user = authenticate_request(request)?;
    user.require_role(required)?;
    Ok(user)
}

fn authenticate_request(request: &HttpRequest) -> Result<AuthenticatedUser, AppError> {
    if let Some(user) = request.extensions().get::<AuthenticatedUser>() {
        return Ok(user.clone());
    }

    let app_state = request
        .app_data::<web::Data<AppState>>()
        .ok_or(AppError::Internal)?;
    let token = bearer_token(request)?;
    let claims =
        validate_access_token(token, &app_state.settings).map_err(|_| invalid_access_token())?;
    let user = AuthenticatedUser::from_claims(claims.clone())?;

    let mut extensions = request.extensions_mut();
    extensions.insert(claims);
    extensions.insert(user.clone());

    Ok(user)
}

fn bearer_token(request: &HttpRequest) -> Result<&str, AppError> {
    let header = request
        .headers()
        .get("authorization")
        .ok_or_else(|| AppError::Unauthorized("missing bearer token".to_string()))?
        .to_str()
        .map_err(|_| invalid_bearer_token())?;

    header
        .strip_prefix("Bearer ")
        .filter(|token| !token.trim().is_empty() && token.trim() == *token)
        .ok_or_else(invalid_bearer_token)
}

fn invalid_access_token() -> AppError {
    AppError::Unauthorized("invalid access token".to_string())
}

fn invalid_bearer_token() -> AppError {
    AppError::Unauthorized("invalid bearer token".to_string())
}

fn forbidden() -> AppError {
    AppError::Forbidden("insufficient permissions".to_string())
}

#[cfg(test)]
mod tests {
    use super::AuthenticatedUser;
    use crate::auth::claims::{Claims, Role};

    fn claims(role: &str) -> Claims {
        Claims {
            sub: uuid::Uuid::new_v4().to_string(),
            email: "person@example.com".to_string(),
            role: role.to_string(),
            exp: 4_102_444_800,
            iat: Some(1_700_000_000),
        }
    }

    #[test]
    fn authenticated_user_rejects_unknown_role() {
        let error =
            AuthenticatedUser::from_claims(claims("owner")).expect_err("unknown role should fail");

        assert!(matches!(error, crate::errors::AppError::Unauthorized(_)));
    }

    #[test]
    fn authenticated_user_role_gate_allows_admin_to_user_route() {
        let user =
            AuthenticatedUser::from_claims(claims("admin")).expect("admin claims should be valid");

        assert!(user.require_role(Role::User).is_ok());
        assert!(user.require_role(Role::Service).is_err());
    }
}
