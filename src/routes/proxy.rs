use actix_web::{http::Method, web};

use crate::handlers::proxy_handler::proxy;

pub fn proxy_routes(cfg: &mut web::ServiceConfig) {
    for path in [
        "/users",
        "/users/{tail:.*}",
        "/payments",
        "/payments/{tail:.*}",
    ] {
        cfg.service(proxy_resource(path));
    }
}

fn proxy_resource(path: &'static str) -> actix_web::Resource {
    web::resource(path)
        .route(web::get().to(proxy))
        .route(web::post().to(proxy))
        .route(web::put().to(proxy))
        .route(web::patch().to(proxy))
        .route(web::delete().to(proxy))
        .route(web::head().to(proxy))
        .route(web::method(Method::OPTIONS).to(proxy))
}
