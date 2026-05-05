use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

pub async fn init_postgres_pool(database_url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await
}