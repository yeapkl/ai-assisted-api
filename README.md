# Authenticated Hello World API

A small, security-conscious reference API: register → login (JWT access +
refresh tokens) → call a protected `Hello World` endpoint that returns the
current server time.

Built by a simulated BA → Developer → QA → Pentester → Reviewer pipeline —
see `docs/` for each phase's output (technical requirements, pentest
report, final review). The implementation was later ported from Python to
Java 21, preserving behavior and the full test suite — see
`docs/JAVA_PORT_NOTES.md`.

## Quick start

```bash
cp .env.example .env
# edit .env: set JWT_SECRET_KEY to a real random value, e.g.
openssl rand -hex 32

mvn compile exec:java -Dexec.mainClass=app.Main   # dev server on http://localhost:8000
```

Production: build a jar and run it behind TLS/a reverse proxy, with
`APP_ENV=production` in the environment:

```bash
mvn package -DskipTests
JWT_SECRET_KEY=... APP_ENV=production java -jar target/hello-world-api.jar
```

The server uses a virtual-thread-per-request executor (Java 21), so no
separate multi-worker process manager (like gunicorn) is needed.

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
mvn test
```

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/health` | none | Liveness check |
| POST | `/api/v1/auth/register` | none | Create a user (rate-limited) |
| POST | `/api/v1/auth/login` | none | Exchange credentials for tokens (rate-limited) |
| POST | `/api/v1/auth/refresh` | none | Exchange refresh token for new access token (rate-limited) |
| GET | `/api/v1/hello` | Bearer access token | Returns greeting + current UTC time |

## Project layout

```
src/main/java/app/
  Config.java       — environment-driven configuration
  Security.java     — password hashing (PBKDF2) + JWT issuance/verification
  Store.java        — in-memory user store
  RateLimiter.java  — in-process sliding-window rate limiter
  JsonUtil.java      — minimal flat-JSON parse/write (no external dependency)
  ApiServer.java    — routes, request handling, security headers
  Main.java         — entry point
src/test/java/app/
  SecurityTest.java        — unit tests for crypto/JWT
  ApiIntegrationTest.java  — integration tests against a real running server
```

## Documentation index

- `docs/requirements/hello-world-api.md` — BA's technical requirements from the business ask
- `docs/JAVA_PORT_NOTES.md` — how and why this was ported from Python to Java
- `docs/DEV_NOTES.md` — original (Python) dev notes on the environment-driven stack substitution
- `docs/qa/hello-world-api-report.md` — QA verification report (from the original Python build)
- `docs/pentest/hello-world-api-report.md` — pentest findings, including one real vulnerability found and fixed (ported and re-verified in Java — see `docs/JAVA_PORT_NOTES.md`)
- `docs/review/hello-world-api-review.md` — final reviewer sign-off (original Python build)
- `docs/BEST_PRACTICES_AND_ROADMAP.md` — best practices applied + improvement plan for production

## The agent pipeline

This repo includes `.claude/agents/` — five isolated Claude Code subagents
(`ba`, `developer`, `qa`, `pentester`, `reviewer`) that build and verify
future features the same way this one was built, but with genuine role
isolation (each runs in its own context, sharing only the documents handed
between stages — see `.claude/agents/README.md`). To build the next
feature: open Claude Code in this repo and ask it to run the ba → developer
→ qa → pentester → reviewer chain on your next requirement.
