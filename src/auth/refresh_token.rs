use argon2::password_hash::rand_core::{OsRng, RngCore};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::Sha256;

const REFRESH_TOKEN_BYTES: usize = 64;

type HmacSha256 = Hmac<Sha256>;

pub fn generate_refresh_token() -> String {
    let mut bytes = [0_u8; REFRESH_TOKEN_BYTES];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn hash_refresh_token(token: &str, secret: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(token.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::{generate_refresh_token, hash_refresh_token};

    #[test]
    fn refresh_token_hash_is_deterministic_and_does_not_store_raw_token() {
        let token = generate_refresh_token();
        let hash = hash_refresh_token(&token, "test-refresh-secret");

        assert_eq!(hash, hash_refresh_token(&token, "test-refresh-secret"));
        assert_ne!(hash, token);
        assert!(!hash.contains(&token));
    }

    #[test]
    fn generated_refresh_tokens_have_enough_entropy_encoded() {
        let token = generate_refresh_token();

        assert!(token.len() >= 80);
        assert_ne!(token, generate_refresh_token());
    }
}
