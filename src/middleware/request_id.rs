use std::{
    future::{Future, Ready, ready},
    pin::Pin,
    rc::Rc,
    time::Instant,
};

use actix_web::{
    Error, HttpMessage,
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    http::header::{HeaderName, HeaderValue},
};
use uuid::Uuid;

use crate::middleware::request_context::RequestContext;

pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

#[derive(Debug, Clone, Default)]
pub struct RequestId;

impl RequestId {
    pub fn new() -> Self {
        Self
    }
}

impl<S, B> Transform<S, ServiceRequest> for RequestId
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = RequestIdMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequestIdMiddleware {
            service: Rc::new(service),
        }))
    }
}

pub struct RequestIdMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for RequestIdMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, request: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let request_id =
            request_id_from_header(&request).unwrap_or_else(|| Uuid::new_v4().to_string());

        request.extensions_mut().insert(RequestContext {
            request_id: request_id.clone(),
            started_at: Instant::now(),
        });

        Box::pin(async move {
            let mut response = service.call(request).await?;
            if let Ok(value) = HeaderValue::from_str(&request_id) {
                response.headers_mut().insert(REQUEST_ID_HEADER, value);
            }
            Ok(response)
        })
    }
}

fn request_id_from_header(request: &ServiceRequest) -> Option<String> {
    request
        .headers()
        .get(REQUEST_ID_HEADER)?
        .to_str()
        .ok()
        .filter(|value| is_valid_request_id(value))
        .map(ToString::to_string)
}

fn is_valid_request_id(value: &str) -> bool {
    value.trim() == value && Uuid::parse_str(value).is_ok()
}

#[cfg(test)]
mod tests {
    use super::{REQUEST_ID_HEADER, RequestId, is_valid_request_id};
    use crate::middleware::request_context::RequestContext;
    use actix_web::{App, HttpMessage, HttpResponse, http::StatusCode, test, web};
    use uuid::Uuid;

    async fn context_echo(request: actix_web::HttpRequest) -> HttpResponse {
        let request_id = request
            .extensions()
            .get::<RequestContext>()
            .map(|context| context.request_id.clone())
            .expect("request context should be present");

        HttpResponse::Ok().body(request_id)
    }

    #[actix_web::test]
    async fn preserves_valid_client_request_id() {
        let client_request_id = Uuid::new_v4().to_string();
        let app = test::init_service(
            App::new()
                .wrap(RequestId::new())
                .route("/echo", web::get().to(context_echo)),
        )
        .await;

        let request = test::TestRequest::get()
            .uri("/echo")
            .insert_header((REQUEST_ID_HEADER, client_request_id.as_str()))
            .to_request();
        let response = test::call_service(&app, request).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(REQUEST_ID_HEADER),
            Some(&client_request_id.parse().expect("valid header value"))
        );
        assert_eq!(
            test::read_body(response).await.as_ref(),
            client_request_id.as_bytes()
        );
    }

    #[actix_web::test]
    async fn replaces_missing_or_invalid_request_id_with_uuid() {
        let app = test::init_service(
            App::new()
                .wrap(RequestId::new())
                .route("/echo", web::get().to(context_echo)),
        )
        .await;

        let request = test::TestRequest::get()
            .uri("/echo")
            .insert_header((REQUEST_ID_HEADER, "not-a-request-id"))
            .to_request();
        let response = test::call_service(&app, request).await;

        assert_eq!(response.status(), StatusCode::OK);
        let response_request_id = response
            .headers()
            .get(REQUEST_ID_HEADER)
            .expect("response should include request ID")
            .to_str()
            .expect("request ID should be a valid header value")
            .to_string();

        assert_ne!(response_request_id, "not-a-request-id");
        assert!(Uuid::parse_str(&response_request_id).is_ok());
        assert_eq!(
            test::read_body(response).await.as_ref(),
            response_request_id.as_bytes()
        );
    }

    #[actix_web::test]
    async fn request_id_validation_accepts_uuid_values_only() {
        assert!(is_valid_request_id(&Uuid::new_v4().to_string()));
        assert!(!is_valid_request_id(" "));
        assert!(!is_valid_request_id("abc123"));
        assert!(!is_valid_request_id(&format!(" {} ", Uuid::new_v4())));
    }
}
