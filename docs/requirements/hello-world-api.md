# Technical Requirements — Authenticated "Hello World" API

**Author:** BA role · **Input:** High-level business request
**Business ask:** "Build me an API with authentication, credential handling via API. The API should start with returning Hello World with the current time."

## 1. Scope
A minimal but production-shaped REST API demonstrating secure authentication and credential handling, exposing one protected business endpoint (`Hello World` + server time).

## 2. Functional Requirements

| ID | Requirement |
|----|-------------|
| FR-1 | System issues short-lived access tokens (JWT) after verifying username/password. |
| FR-2 | System issues a refresh token to obtain new access tokens without re-sending credentials. |
| FR-3 | `GET /api/v1/hello` returns `{"message": "Hello, <user>!", "server_time_utc": "<ISO-8601>"}` and requires a valid access token. |
| FR-4 | `POST /api/v1/auth/register` creates a user with a hashed password (demo user store). |
| FR-5 | `POST /api/v1/auth/login` exchanges credentials for tokens. |
| FR-6 | `POST /api/v1/auth/refresh` exchanges a refresh token for a new access token. |
| FR-7 | `GET /health` is unauthenticated, for liveness checks. |

## 3. Non-Functional / Security Requirements

| ID | Requirement |
|----|-------------|
| NFR-1 | Passwords stored only as salted bcrypt hashes — never plaintext, never logged. |
| NFR-2 | JWT signing secret loaded from environment/`.env`, never hardcoded, never committed. |
| NFR-3 | Access tokens expire in 15 min; refresh tokens in 7 days. |
| NFR-4 | All auth failures return generic `401`, no user-enumeration hints. |
| NFR-5 | Rate limiting on `/auth/*` endpoints to reduce brute-force risk. |
| NFR-6 | Security headers on all responses (HSTS, X-Content-Type-Options, etc.). |
| NFR-7 | Input validated via typed schemas (Pydantic); reject malformed payloads with `422`. |
| NFR-8 | CORS explicit allow-list, not wildcard, when credentials are involved. |
| NFR-9 | No sensitive data (passwords, tokens) in application logs. |
| NFR-10 | Dependency and static-security scan run before release. |

## 4. Out of Scope (flagged for improvement plan)
- Persistent database (demo uses in-memory store — swap for Postgres in production).
- Full OAuth2/social login, MFA, password-reset flow.
- Distributed rate limiting (demo uses in-process limiter).

## 5. Handoff to Developer
Stack: **Python 3.11 + FastAPI** (async, typed, auto OpenAPI docs — good fit for a small secure demo).
Auth: **OAuth2 Password flow + JWT (HS256)**, `passlib[bcrypt]` for hashing.
