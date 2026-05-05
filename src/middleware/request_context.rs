use std::time::Instant;

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub request_id: String,
    pub started_at: Instant,
}
