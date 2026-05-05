# Sentinel API Gateway

Sentinel API Gateway is a Rust web service built with Actix Web. The project is structured as an API gateway with authentication, PostgreSQL persistence, Redis connectivity, and room for future proxy, rate limiting, audit, and admin features.

At the moment, the implemented HTTP surface focuses on health checks and user authentication:

- `GET /health`
- `POST /auth/register`
- `POST /auth/login`

## Tech Stack

- Rust 2024 edition
- Actix Web for the HTTP server
- Tokio for async runtime support
- SQLx with PostgreSQL
- Redis client for cache/connectivity support
- Argon2 for password hashing
- JSON Web Tokens for access tokens
- dotenvy for local environment loading
- tracing and tracing-subscriber for application logging

## Project Structure

```text
src/
  app/             Shared application state
  auth/            Password hashing and JWT helpers
  cache/           Redis initialization
  config/          Environment-based settings
  db/              PostgreSQL pool initialization
  errors/          Application error types
  handlers/        HTTP request handlers
  models/          Request, response, and database models
  repositories/    Database access layer
  routes/          Route registration
  services/        Business logic
  telemetry/       Tracing/logging setup
```

Admin routes and deployment-oriented gateway features are still future work.

## Prerequisites

Install the following before running the project:

- Rust and Cargo
- Docker and Docker Compose
- PostgreSQL client tooling, if you want to inspect the database manually

## Configuration

Create a local `.env` file from `.env.example`:

```bash
cp .env.example .env
```

Default local configuration:

```env
APP_HOST=127.0.0.1
APP_PORT=8080

DATABASE_URL=postgres://postgres:postgres@localhost:5432/sentinel_gateway
REDIS_URL=redis://127.0.0.1:6379

JWT_ACCESS_SECRET=change_me_access_secret
JWT_REFRESH_SECRET=change_me_refresh_secret

ACCESS_TOKEN_TTL_MINUTES=15
REFRESH_TOKEN_TTL_DAYS=7

USER_SERVICE_URL=http://localhost:8081
PAYMENT_SERVICE_URL=http://localhost:8082

PROXY_TIMEOUT_SECONDS=10
PROXY_FORWARD_AUTH_HEADER=false
PROXY_MAX_BODY_BYTES=10485760

RATE_LIMIT_ENABLED=true
RATE_LIMIT_ANON_PER_MINUTE=60
RATE_LIMIT_AUTH_PER_MINUTE=300
RATE_LIMIT_AUTH_ENDPOINT_PER_MINUTE=10
RATE_LIMIT_WINDOW_SECONDS=60
RATE_LIMIT_REDIS_PREFIX=rate_limit
```

For real environments, replace the JWT secrets with strong secret values.
Rate limiting uses Redis fixed-window counters and is enabled by default.

## Running Locally

Start PostgreSQL and Redis:

```bash
docker compose up -d
```

Run database migrations:

```bash
sqlx migrate run
```

Start the API server:

```bash
cargo run
```

The server binds to the address returned by `APP_HOST` and `APP_PORT`, which defaults to:

```text
http://127.0.0.1:8080
```

## API Endpoints

### Health Check

```http
GET /health
```

Checks PostgreSQL and Redis connectivity.

Example successful response:

```json
{
  "status": "ok",
  "database": "up",
  "redis": "up"
}
```

If either dependency is unavailable, the endpoint returns `503 Service Unavailable` with `status` set to `degraded`.

### Register

```http
POST /auth/register
Content-Type: application/json
```

Request body:

```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

Successful response:

```json
{
  "id": "generated-user-id",
  "email": "user@example.com",
  "role": "user",
  "created_at": "timestamp"
}
```

Validation rules:

- Email and password are required.
- Password must be at least 8 characters.
- Email addresses are normalized to lowercase.
- Duplicate emails are rejected.

### Login

```http
POST /auth/login
Content-Type: application/json
```

Request body:

```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

Successful response:

```json
{
  "access_token": "jwt-token",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "id": "user-id",
    "email": "user@example.com",
    "role": "user",
    "created_at": "timestamp"
  }
}
```

## Database

The initial migration creates a `users` table:

```sql
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

## Development Notes

Run a compile check with:

```bash
cargo check
```

Run formatting with:

```bash
cargo fmt
```

Run tests with:

```bash
cargo test
```

Current implementation note: `AppState` and `main.rs` need to stay in sync. If `AppState` includes shared repositories or services, initialize those fields in `main.rs`; otherwise, remove unused fields from `AppState`.

## Roadmap

Planned gateway features suggested by the current module layout:

- Auth middleware for protected routes
- Refresh token persistence and rotation
- Reverse proxy forwarding
- Upstream service routing
- Request ID and structured request logging middleware
- Audit logging
- Admin endpoints

## License

No license has been specified yet.
