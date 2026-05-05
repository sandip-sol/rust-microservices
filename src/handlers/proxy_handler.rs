use actix_web::{HttpRequest, HttpResponse, web};
use bytes::Bytes;

use crate::{
    app::state::AppState, errors::AppError, middleware::auth::AuthenticatedUser, proxy::forwarder,
};

pub async fn proxy(
    request: HttpRequest,
    body: Bytes,
    user: AuthenticatedUser,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse, AppError> {
    forwarder::forward(request, body, user, app_state).await
}
