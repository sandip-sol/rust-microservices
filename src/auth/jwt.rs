use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};

use crate::{
    config::settings::Settings,
    models::auth::JwtClaims,
    models::user::User,
};

pub fn generate_access_token(
    user: &User,
    settings: &Settings,
) -> Result<(String, i64), jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let expires_in = settings.access_token_ttl_minutes * 60;
    let exp = (now + Duration::minutes(settings.access_token_ttl_minutes)).timestamp() as usize;

    let claims = JwtClaims {
        sub: user.id,
        email: user.email.clone(),
        role: user.role.clone(),
        iat: now.timestamp() as usize,
        exp,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(settings.jwt_access_secret.as_bytes()),
    )?;

    Ok((token, expires_in))
}

pub fn validate_access_token(
    token: &str,
    settings: &Settings,
) -> Result<JwtClaims, jsonwebtoken::errors::Error> {
    let token_data = decode::<JwtClaims>(
        token,
        &DecodingKey::from_secret(settings.jwt_access_secret.as_bytes()),
        &Validation::default(),
    )?;

    Ok(token_data.claims)
}
