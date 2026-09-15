# Port notes: Python → Java

The API was originally built in Python (Flask + stdlib crypto, see
`docs/DEV_NOTES.md`) by the BA → Developer → QA → Pentester → Reviewer
pipeline. It was subsequently ported to Java 21, preserving behavior,
endpoints, and security properties. This document records that port; the
other `docs/` reports (requirements, QA, pentest, review) describe the
original Python build and the requirements/findings that still apply
to this Java implementation.

## Stack mapping

| Python | Java | Notes |
|---|---|---|
| Flask (WSGI) | `com.sun.net.httpserver.HttpServer` (JDK) | Both are small, unopinionated HTTP layers; the JDK's built-in server avoids any runtime dependency, same rationale as the original Flask-instead-of-FastAPI substitution. |
| `hmac`/`hashlib` hand-rolled JWT | Hand-rolled HS256 JWT in `Security.java` (`javax.crypto.Mac`, `Base64`) | Same envelope (header.payload.signature, HMAC-SHA256), same constant-time signature comparison, same `alg=none` forgery resistance (the verifier always signs with HS256 regardless of the token's own header). |
| `hashlib.pbkdf2_hmac` | `javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")` | Same algorithm, same iteration count (260,000), same random 16-byte salt, same stored format (`pbkdf2_sha256$iterations$salt$digest`). |
| `app/rate_limit.py` sliding window | `RateLimiter.java` sliding window | Same per-key, per-window semantics; still a single-process, in-memory limiter — the production improvement plan (shared Redis-backed limiter) applies equally here. |
| Pydantic schemas | Manual field validation in `ApiServer.java` | Same constraints: username 3-32 chars, `^[a-zA-Z0-9_]+$`; password 8-128 chars. |
| pydantic-settings `Settings` | `Config.java` | Same required/optional env vars, same "fail fast if `JWT_SECRET_KEY` is missing or under 32 chars" behavior, same `.env` file support. |
| `unittest` (22 tests) | JUnit 5 (22 tests: `SecurityTest` + `ApiIntegrationTest`) | Every test case from `tests/test_api.py` has a direct equivalent, run against a real running server via `java.net.http.HttpClient` instead of Flask's test client. |

## What carried over unchanged

All functional and non-functional requirements (FR-1..FR-7, NFR-1..NFR-7)
from `docs/requirements/hello-world-api.md` apply unchanged to the Java
implementation, and the Java test suite (`mvn test`) verifies every one of
them, including the two security-relevant fixes from the original pipeline:

- **No user enumeration** (NFR-4): identical error body and status for
  wrong-password vs. unknown-username.
- **Login timing side-channel fix** (pentest finding): a fixed dummy hash
  is always compared against for unknown usernames, so the password-hash
  comparison always runs — ported verbatim into `ApiServer.handleLogin`.

## Why zero runtime dependencies again

The original Python build used only Flask (already installed) plus the
standard library, because this environment's network policy blocked PyPI.
Maven Central *is* reachable from this environment, so a framework like
Spring Boot was an option — but the port keeps the same zero-runtime-dependency
posture deliberately: the security-critical code here (password hashing,
JWT signing/verification) is small enough to read in one sitting, and every
line of a hand-rolled crypto primitive is a line someone has to audit
forever. JUnit 5 is a test-only dependency and never ships in the runtime
jar.

**Before deploying anywhere real:** the same caveat from `docs/DEV_NOTES.md`
applies — consider swapping the hand-rolled JWT/PBKDF2 code for a
well-audited library (e.g. `com.auth0:java-jwt`, Spring Security's
`PasswordEncoder`) if your organization's policy prefers widely-used
dependencies over in-house crypto glue.
