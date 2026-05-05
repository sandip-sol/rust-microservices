use std::env;

#[derive(Debug, Clone)]
pub struct Settings {
    pub app_host: String,
    pub app_port: u16,
    pub database_url: String,
    pub redis_url: String,
    pub jwt_access_secret: String,
    pub jwt_refresh_secret: String,
    pub access_token_ttl_minutes: i64,
    pub refresh_token_ttl_days: i64,
    pub user_service_url: String,
    pub payment_service_url: String,
}

impl Settings {
    pub fn from_env() -> Self {
        dotenvy::dotenv().ok();

        Self {
            app_host: env::var("APP_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            app_port: env::var("APP_PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()
                .expect("APP_PORT must be a valid u16"),

            database_url: env::var("DATABASE_URL")
                .expect("DATABASE_URL is required"),

            redis_url: env::var("REDIS_URL")
                .expect("REDIS_URL is required"),

            jwt_access_secret: env::var("JWT_ACCESS_SECRET")
                .expect("JWT_ACCESS_SECRET is required"),

            jwt_refresh_secret: env::var("JWT_REFRESH_SECRET")
                .expect("JWT_REFRESH_SECRET is required"),

            access_token_ttl_minutes: env::var("ACCESS_TOKEN_TTL_MINUTES")
                .unwrap_or_else(|_| "15".to_string())
                .parse()
                .expect("ACCESS_TOKEN_TTL_MINUTES must be valid"),

            refresh_token_ttl_days: env::var("REFRESH_TOKEN_TTL_DAYS")
                .unwrap_or_else(|_| "7".to_string())
                .parse()
                .expect("REFRESH_TOKEN_TTL_DAYS must be valid"),

            user_service_url: env::var("USER_SERVICE_URL")
                .unwrap_or_else(|_| "http://localhost:8081".to_string()),

            payment_service_url: env::var("PAYMENT_SERVICE_URL")
                .unwrap_or_else(|_| "http://localhost:8082".to_string()),
        }
    }

    pub fn app_addr(&self) -> String {
        format!("{}:{}", self.app_host, self.app_port)
    }
}