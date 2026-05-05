use actix_web::web;

use crate::handlers::admin_handler::{
    get_audit_log, get_user, list_audit_logs, list_users, rate_limit_visibility, upstream_health,
};

pub fn admin_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/admin")
            .route("/users", web::get().to(list_users))
            .route("/users/{id}", web::get().to(get_user))
            .route("/audit-logs", web::get().to(list_audit_logs))
            .route("/audit-logs/{id}", web::get().to(get_audit_log))
            .route("/upstreams/health", web::get().to(upstream_health))
            .route("/rate-limits", web::get().to(rate_limit_visibility)),
    );
}
