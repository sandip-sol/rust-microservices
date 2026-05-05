use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};

use crate::{auth::claims::Claims, config::settings::Settings, models::user::User};

pub fn generate_access_token(
    user: &User,
    settings: &Settings,
) -> Result<(String, i64), jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let expires_in = settings.access_token_ttl_minutes * 60;
    let exp = (now + Duration::minutes(settings.access_token_ttl_minutes)).timestamp() as usize;

    let claims = Claims {
        sub: user.id.to_string(),
        email: user.email.clone(),
        role: user.role.clone(),
        iat: Some(now.timestamp() as usize),
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
) -> Result<Claims, jsonwebtoken::errors::Error> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(settings.jwt_access_secret.as_bytes()),
        &Validation::default(),
    )?;

    Ok(token_data.claims)
}
