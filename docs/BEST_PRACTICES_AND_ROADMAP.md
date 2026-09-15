# Best Practices Applied + Improvement Plan

## Best practices already built in

**Authentication & credentials**
- Passwords never stored in plaintext; PBKDF2-HMAC-SHA256 (260k iterations) with a unique random salt per password.
- JWT access/refresh split: short-lived access token (15 min) limits the blast radius of a leaked token; refresh token (7 days) avoids re-sending credentials on every request.
- Token signatures always verified with constant-time comparison (`hmac.compare_digest`) — prevents timing attacks on signature checks.
- Generic, identical error responses **and** equalized timing on auth failures — prevents username enumeration (a real timing side-channel was found and fixed during the pentest phase, see `PENTEST_REPORT.md`).
- Secrets sourced only from environment/`.env`, validated at startup (min length), never hardcoded, `.env` gitignored.

**API hygiene**
- Strict, typed request validation (Pydantic) rejects malformed/oversized input before it reaches business logic.
- Per-IP rate limiting on all auth endpoints.
- Baseline security headers on every response (`nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Cache-Control: no-store`, HSTS in production).
- Explicit CORS origin allow-list rather than a wildcard.
- Clean separation of concerns (auth, storage, schemas, rate limiting, routes) so components can be swapped independently.

**Process**
- Requirements traced to numbered FR/NFR IDs referenced directly in code comments, so a reviewer or auditor can map every control back to a requirement.
- Automated test suite (22 tests) covering the happy path, every documented negative case, and the security properties themselves (timing, tampering, enumeration).

## Improvement plan (prioritized for a real production rollout)

### 1. Before production (must-do)
- **Run dependency & static-security scanning in CI** (`pip-audit`, `bandit`, or equivalent) — this sandbox's network policy blocked it here; it must run somewhere with normal package-index access before shipping.
- **Swap the in-memory user store for a real database** (Postgres via SQLAlchemy is a solid default) with connection pooling and migrations (Alembic). Current store is not persistent and not safe for multiple processes.
- **Move rate limiting to shared state** (Redis) — the current in-process limiter resets per worker/replica, which under-throttles behind a multi-process/multi-instance deployment.
- **Set `APP_ENV=production` and disable debug/reloader** as a hard deploy-gate check (a CI or startup assertion, not just documentation) — debug mode's interactive debugger is an RCE risk if ever exposed.
- **Terminate TLS properly** (managed cert via the cloud provider / reverse proxy) — this demo runs plaintext HTTP locally only.
- **Strip/override the `Server` header** at the reverse proxy to reduce version fingerprinting.

### 2. Near-term hardening
- **Token revocation**: add a denylist (Redis, keyed by the `jti` claim already included in every token) so a compromised token or a logged-out session can be invalidated before natural expiry.
- **Account lockout / backoff** on repeated failed logins per-account, in addition to per-IP rate limiting (defense against distributed/low-and-slow brute force).
- **Structured audit logging** for auth events (login success/failure, registration, token refresh) — without ever logging passwords or full tokens — feeding into a SIEM or at least searchable logs.
- **Password strength policy** beyond length (e.g. check against a breached-password list via k-anonymity, like HaveIBeenPwned's API) and a password-change/reset flow with its own rate limits.
- **Add MFA (TOTP)** as an opt-in second factor.
- **Formal secret rotation**: process for rotating `JWT_SECRET_KEY` without invalidating every session at once (e.g. support two active keys during rotation).

### 3. Operational maturity
- **CI/CD pipeline**: lint (ruff/flake8), type-check (mypy), run the test suite, run security scans, build, deploy — every merge to main.
- **Observability**: metrics (request rate, error rate, auth failure rate, latency) and alerting on anomalies (e.g. spike in 401s = possible credential-stuffing attempt).
- **Load testing** to validate the rate limiter and server under realistic and adversarial traffic before go-live.
- **Regular re-pentesting** — this was a point-in-time review; schedule recurring assessments as the API grows (new endpoints, new data, new integrations).
- **Threat modeling** each new feature (STRIDE or similar) before it ships, not just at the end.

### 4. API design evolution
- **API versioning strategy** beyond the `/v1/` prefix already in place — deprecation policy, sunset headers.
- **OpenAPI/Swagger spec** generated from the schemas for consumer-facing documentation (Flask + `flask-smorest`/`apispec`, or migrate to FastAPI once network access allows, which generates this automatically).
- **Pagination, filtering, and consistent error envelope** conventions once more resource endpoints are added beyond `hello`.
