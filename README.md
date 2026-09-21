# Authenticated Hello World API

[![CI/CD](https://github.com/yeapkl/ai-assisted-api/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/yeapkl/ai-assisted-api/actions/workflows/ci-cd.yml)

A small, security-conscious reference API: register → login (JWT access +
refresh tokens) → call a protected `Hello World` endpoint that returns the
current server time.

Built by a simulated BA → Developer → QA → Pentester → Reviewer pipeline —
see `docs/` for each phase's output (technical requirements, pentest
report, final review). The implementation was first ported from Python to
a zero-dependency Java 21 build (see `docs/JAVA_PORT_NOTES.md`), then
rebuilt on **Spring Boot 3.x / Java 21**, delegating every cross-cutting
concern (JSON, JWT, password hashing, rate limiting, request validation,
security headers/CORS) to an established library instead of hand-rolled
code — see `docs/requirements/hello-world-api.md` (2026-09 revision) and
`docs/JAVA_PORT_NOTES.md` for that migration's rationale.

[![MCP Server CI/CD](https://github.com/yeapkl/ai-assisted-api/actions/workflows/mcp-ci-cd.yml/badge.svg)](https://github.com/yeapkl/ai-assisted-api/actions/workflows/mcp-ci-cd.yml)

An [MCP server](mcp-server/README.md) also wraps this API's endpoints as
tools an AI agent can call directly - see `mcp-server/README.md` and
`docs/deploy/mcp-server-setup.md` for what it exposes and how to reach it
(it requires GCP authentication, unlike the main API).

## Quick start

```bash
cp .env.example .env
# edit .env: set JWT_SECRET_KEY to a real random value, e.g.
openssl rand -hex 32

mvn spring-boot:run   # dev server on http://localhost:8000
```

`.env` is picked up automatically on startup (see
`com.apitest.ApiApplication`) — no need to `export`/`source` it yourself,
though real process environment variables always take precedence over it.

Production: build a jar and run it behind TLS/a reverse proxy, with
`APP_ENV=production` in the environment:

```bash
mvn package -DskipTests
JWT_SECRET_KEY=... APP_ENV=production java -jar target/hello-world-api.jar
```

The server runs on an embedded Tomcat (Spring Boot's default), configured
via `src/main/resources/application.yml`.

### Run with Docker

Every push to `main` that passes CI builds and publishes an image to GitHub
Container Registry:

```bash
docker pull ghcr.io/yeapkl/ai-assisted-api:latest
docker run -p 8000:8000 -e JWT_SECRET_KEY=$(openssl rand -hex 32) ghcr.io/yeapkl/ai-assisted-api:latest
```

Or build it locally from the `Dockerfile`:

```bash
docker build -t hello-world-api .
docker run -p 8000:8000 -e JWT_SECRET_KEY=$(openssl rand -hex 32) hello-world-api
```

### Live test deployment (Google Cloud Run)

Every push to `main` also deploys the image to a free-tier Cloud Run
service, authenticating via Workload Identity Federation (no GCP key
stored in GitHub). See `docs/deploy/gcp-cloud-run-setup.md` for the
one-time `gcloud` setup and how to find the deployed URL.

## Try it

```bash
# Register
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"S3cur3Passw0rd!"}'

# Login -> get tokens
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"S3cur3Passw0rd!"}'

# Call the protected endpoint
curl http://localhost:8000/api/v1/hello -H "Authorization: Bearer <access_token>"
# => {"message": "Hello, alice!", "server_time_utc": "2026-09-15T15:32:22...Z"}
```

## Run the tests

```bash
mvn test        # unit + Spring Boot integration tests (random port, real HTTP calls)
mvn package     # test + build target/hello-world-api.jar
```

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/health` | none | Liveness check |
| POST | `/api/v1/auth/register` | none | Create a user (rate-limited) |
| POST | `/api/v1/auth/login` | none | Exchange credentials for tokens (rate-limited) |
| POST | `/api/v1/auth/refresh` | none | Exchange refresh token for new access token (rate-limited) |
| GET | `/api/v1/hello` | Bearer access token (either the JSON API's own jjwt token, or an OAuth access token — see below) | Returns greeting + current UTC time |
| GET | `/.well-known/oauth-authorization-server` | none | RFC 8414 OAuth Authorization Server metadata |
| GET | `/oauth2/authorize` | browser session (HTML login form) | OAuth 2.1 `authorization_code`+PKCE authorization endpoint |
| POST | `/oauth2/token` | pre-registered client credentials + PKCE | OAuth 2.1 `authorization_code`/`refresh_token` token endpoint |

The OAuth 2.1 Authorization Server (`/.well-known/oauth-authorization-server`,
`/oauth2/authorize`, `/oauth2/token`, `/login`) is an additive capability so
`mcp-server` (or any other OAuth 2.1 client) can authenticate end users via a
standards-based browser-redirect flow instead of raw tool arguments — see
`docs/requirements/hello-world-api.md` (NFR-13..NFR-20) and
`com.apitest.oauth` for the implementation. It does not change
`/api/v1/auth/*`'s or `/api/v1/hello`'s existing request/response shapes,
status codes, or the original JSON-only auth flow in any way.

## Project layout

```
src/main/java/com/apitest/
  ApiApplication.java          — @SpringBootApplication entry point (+ optional .env loader)
  config/AppProperties.java    — environment-driven configuration, fails fast if JWT_SECRET_KEY missing/short
  config/SecurityConfig.java   — PasswordEncoder bean, Spring Security header/CORS config
  security/JwtService.java     — JWT issuance/verification (io.jsonwebtoken:jjwt)
  security/PasswordService.java— password hashing (Spring Security BCryptPasswordEncoder) + NFR-4 dummy hash
  store/UserStore.java         — in-memory user store
  filter/JwtAuthFilter.java    — bearer-token auth check for /api/v1/hello (accepts either token family)
  filter/RateLimitFilter.java  — Bucket4j-based rate limiting for /api/v1/auth/*
  web/AuthController.java      — register/login/refresh
  web/HelloController.java     — protected greeting endpoint
  web/HealthController.java    — liveness check
  web/GlobalExceptionHandler.java — maps validation/malformed-body/method-not-allowed to the API's error shape
  web/dto/                     — request DTOs with Jakarta Bean Validation annotations
  oauth/                       — OAuth 2.1 Authorization Server (NFR-13..NFR-20, additive)
    OAuthProperties.java          — app.oauth.* config, fails fast on missing/short secrets
    JwkConfig.java                — RSA signing key + JwtDecoder for the OAuth token family
    AuthorizationServerConfig.java— RegisteredClientRepository, security filter chains, aud-claim customizer
    UserStoreUserDetailsService.java — bridges the /login form to the existing UserStore (NFR-17)
    LoginController.java / LoginFailureHandler.java — the one HTML endpoint in this API
    RejectPlainPkceFilter.java    — NFR-18: rejects code_challenge_method=plain
src/main/resources/application.yml — server port, app.* config bound to env vars
src/test/java/com/apitest/
  ApiIntegrationTest.java  — sanity tests against a real running embedded server
Dockerfile, .dockerignore    — multi-stage build, published to GHCR by CI on merge to main
.github/workflows/ci-cd.yml  — build + test on every push/PR, then Docker image publish on main
```

The earlier zero-dependency `com.sun.net.httpserver`-based Java port
(`src/main/java/app/*`) has been retired in favor of this Spring Boot
implementation — see `docs/JAVA_PORT_NOTES.md`.

## Documentation index

- `docs/requirements/hello-world-api.md` — BA's technical requirements from the business ask
- `docs/JAVA_PORT_NOTES.md` — how and why this was ported from Python to Java
- `docs/DEV_NOTES.md` — original (Python) dev notes on the environment-driven stack substitution
- `docs/qa/hello-world-api-report.md` — QA verification report (from the original Python build)
- `docs/pentest/hello-world-api-report.md` — pentest findings, including one real vulnerability found and fixed (ported and re-verified in Java — see `docs/JAVA_PORT_NOTES.md`)
- `docs/review/hello-world-api-review.md` — final reviewer sign-off (original Python build)
- `docs/BEST_PRACTICES_AND_ROADMAP.md` — best practices applied + improvement plan for production
- `docs/deploy/gcp-cloud-run-setup.md` — one-time GCP setup for keyless CI/CD deployment (WIF, service accounts, Secret Manager)
- `docs/deploy/mcp-server-setup.md` — how to reach the MCP server's Cloud Run endpoint (OAuth 2.1 resource-server auth at the application layer, `--allow-unauthenticated` at the Cloud Run/IAM layer)
- `mcp-server/README.md` — the MCP server that wraps this API's endpoints as AI-agent-callable tools

## The agent pipeline

This repo includes `.claude/agents/` — five isolated Claude Code subagents
(`ba`, `developer`, `qa`, `pentester`, `reviewer`) that build and verify
future features the same way this one was built, but with genuine role
isolation (each runs in its own context, sharing only the documents handed
between stages — see `.claude/agents/README.md`). To build the next
feature: open Claude Code in this repo and ask it to run the ba → developer
→ qa → pentester → reviewer chain on your next requirement.
