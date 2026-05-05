use actix_web::{web, HttpResponse, Responder};
use serde::Serialize;

use crate::app::state::AppState;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub database: String,
    pub redis: String,
}

pub async fn health_check(app_state: web::Data<AppState>) -> impl Responder {
    let db_status = match sqlx::query("SELECT 1").fetch_one(&app_state.db_pool).await {
        Ok(_) => "up".to_string(),
        Err(_) => "down".to_string(),
    };

    let redis_status = match app_state
        .redis_client
        .get_multiplexed_async_connection()
        .await
    {
        Ok(mut conn) => {
            let pong: Result<String, _> = redis::cmd("PING").query_async(&mut conn).await;
            match pong {
                Ok(_) => "up".to_string(),
                Err(_) => "down".to_string(),
            }
        }
        Err(_) => "down".to_string(),
    };

    let overall = if db_status == "up" && redis_status == "up" {
        "ok"
    } else {
        "degraded"
    };

    let response = HealthResponse {
        status: overall.to_string(),
        database: db_status,
        redis: redis_status,
    };

    if overall == "ok" {
        HttpResponse::Ok().json(response)
    } else {
        HttpResponse::ServiceUnavailable().json(response)
    }
}
