# Technical Requirements — Authenticated "Hello World" API

**Author:** BA role · **Input:** High-level business request
**Business ask:** "Build me an API with authentication, credential handling via API. The API should start with returning Hello World with the current time."

**Revision note (2026-09):** Product owner directive changed the *implementation
strategy* only: the API must be rebuilt on **Spring Boot**, and every
cross-cutting concern that was previously hand-rolled (rate limiting, JSON
parsing, JWT issuance/verification, password hashing, request validation)
must instead use an established, well-maintained library. No endpoint,
status code, auth flow, or user-facing behavior changes as part of this
revision — see the updated Handoff section (§6) and the new NFR-11.

**Revision note (2026-09, later): OAuth 2.1 Authorization Server.** A second,
ADDITIVE revision: `hello-world-api` gains a standards-based OAuth 2.1
Authorization Server (Spring Authorization Server) so that the `mcp-server`
module (see `docs/requirements/mcp-server.md`) can authenticate MCP clients
via a real browser-redirect OAuth flow instead of passing raw
usernames/passwords/tokens through LLM-visible tool arguments. This does
**not** replace or change FR-1..FR-7 or NFR-1..NFR-10 in any way — see the
Scope note below and new NFR-12..NFR-20.

## 1. Scope
A minimal but production-shaped REST API demonstrating secure authentication
and credential handling, exposing one protected business endpoint
(`Hello World` + server time). As of the first revision, the API is built on
Spring Boot 3.x / Java 21, delegating every security-critical or
cross-cutting primitive (JSON, JWT, password hashing, rate limiting,
validation) to an established library rather than in-house code. In scope:
the functional and non-functional requirements below, unchanged in
behavior. Out of scope: any change to endpoints, request/response shapes,
status codes, or auth semantics — that revision was implementation strategy
only, not a behavior change.

**Scope addition (OAuth Authorization Server):** this revision is strictly
additive on top of the above. The existing JSON `/api/v1/auth/register`,
`/api/v1/auth/login`, and `/api/v1/auth/refresh` endpoints, their request/
response shapes, status codes, rate limiting (NFR-5), timing-safe login
behavior (NFR-4), and generic error bodies (NFR-4, NFR-9) all remain exactly
as specified for direct/non-MCP API consumers — do not remove, rename, or
"clean up" them as part of adding the Authorization Server. In scope for
this addition: new OAuth discovery, authorization, and token endpoints
(§2/§3 below) that let `mcp-server` (and any other OAuth 2.1 client)
authenticate end users against the same underlying `UserStore` via a
standards-compliant flow. Out of scope: Dynamic Client Registration (see
§4), any new grant types beyond `authorization_code` (with PKCE) and
`refresh_token`, and any change to the demo's in-memory persistence model.

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

FR-1..FR-7 are unchanged by both revisions in this document. New OAuth
capability is specified as NFR-12..NFR-20 below (see the note at the top of
§3) rather than as new FR numbers, so that FR-1..FR-7 continue to identify
exactly the original, already-reviewed JSON API surface.

## 3. Non-Functional / Security Requirements

| ID | Requirement |
|----|-------------|
| NFR-1 | Passwords stored only as salted hashes produced by an established password-hashing library exposed through Spring Security's `PasswordEncoder` abstraction (e.g. `BCryptPasswordEncoder`) — never plaintext, never logged, never a hand-rolled hashing routine. |
| NFR-2 | JWT signing secret loaded from environment/`.env`, never hardcoded, never committed; access and refresh tokens are issued and verified using an established JWT library (e.g. `io.jsonwebtoken:jjwt`, Nimbus JOSE+JWT, or Spring Security's OAuth2 resource server support), not hand-rolled HMAC signing/parsing code. |
| NFR-3 | Access tokens expire in 15 min; refresh tokens in 7 days. |
| NFR-4 | All auth failures return generic `401`, no user-enumeration hints (identical response for unknown username vs. wrong password; a fixed dummy hash comparison runs on the unknown-username path so response timing does not leak which case occurred). |
| NFR-5 | Rate limiting on `/auth/*` endpoints is implemented with an established rate-limiting library (e.g. Bucket4j or Resilience4j `RateLimiter`), not an in-house sliding-window implementation, to reduce brute-force risk. |
| NFR-6 | Security headers on all responses (HSTS, X-Content-Type-Options, etc.), applied via Spring Security's standard header configuration rather than hand-written response-header code. |
| NFR-7 | Input validated via Jakarta Bean Validation annotations (`spring-boot-starter-validation`, e.g. `@NotBlank`, `@Size`, `@Pattern` on request DTOs) rather than manual field-by-field checks; reject malformed payloads with `422` and a field-level error body. |
| NFR-8 | CORS explicit allow-list, not wildcard, when credentials are involved. |
| NFR-9 | No sensitive data (passwords, tokens, JWT secret) in application logs or error responses. |
| NFR-10 | Dependency and static-security scan run before release (now meaningful in practice, since the dependency tree is no longer empty). |
| NFR-11 | No hand-rolled implementations of security-critical or cross-cutting primitives — JSON parsing/serialization, JWT issuance/verification, password hashing, rate limiting, and request validation must each be delegated to an established, actively-maintained library named in §6, not custom/in-house code. Verifiable by inspecting the build file's dependency list and confirming the codebase contains no custom JSON parser, custom JWT signer/verifier, custom password-hashing routine, or custom sliding-window/token-bucket limiter. |

### OAuth 2.1 Authorization Server (additive — see Scope, §1)

| ID | Requirement |
|----|-------------|
| NFR-12 | Adding the Authorization Server must not change the request/response shape, status codes, or behavior of `/api/v1/auth/register`, `/api/v1/auth/login`, `/api/v1/auth/refresh`, or `/api/v1/hello`. Verifiable: the existing hello-world-api test suite (covering FR-1..FR-7, NFR-1..NFR-10) passes unmodified after this addition. |
| NFR-13 | `GET /.well-known/oauth-authorization-server` returns an unauthenticated `200` with OAuth 2.0 Authorization Server Metadata (RFC 8414) JSON, including at minimum `issuer`, `authorization_endpoint`, `token_endpoint`, `response_types_supported` (must include `code`), `grant_types_supported` (must include `authorization_code` and `refresh_token`), and `code_challenge_methods_supported` (must include `S256`). |
| NFR-14 | `GET /oauth2/authorize` (with valid `response_type=code`, `client_id`, `redirect_uri`, `code_challenge`, `code_challenge_method=S256` query parameters) renders an HTML login form when the caller is not already authenticated in the browser session. This is a real, intentional behavior change from today's JSON-only API: this one endpoint serves HTML, not JSON. Submitting valid credentials redirects (`302`) to `redirect_uri` with an authorization `code` and the original `state` parameter; invalid credentials re-render the form with a generic error message (no user-enumeration hint, consistent with NFR-4's intent) and do not redirect. |
| NFR-15 | `POST /oauth2/token` with `grant_type=authorization_code`, a valid `code`, matching `redirect_uri`, and the correct PKCE `code_verifier` returns `200` with a JSON body containing `access_token`, `token_type=Bearer`, `expires_in`, and (when requested) `refresh_token`. An invalid/expired/already-used code, a mismatched `redirect_uri`, or a missing/incorrect `code_verifier` returns `400` with an OAuth-standard `error` body (e.g. `invalid_grant`) — never a `500` or a stack trace. |
| NFR-16 | `POST /oauth2/token` with `grant_type=refresh_token` and a valid refresh token issued by this Authorization Server returns a new access token per RFC 6749 §6, so that MCP (and other OAuth) clients can renew access without re-running the browser login flow. |
| NFR-17 | The `/oauth2/authorize` login form authenticates against the **same** `UserStore` and password hashes already used by `/api/v1/auth/login` (i.e., a single set of users, one password per account) — not a second, independently-provisioned set of OAuth users. A user registered via `POST /api/v1/auth/register` must be able to log in successfully via the OAuth form with the same credentials, and a password change (if ever added) must apply to both paths identically. |
| NFR-18 | PKCE (RFC 7636, `S256` only — `plain` must be rejected) is confirmed enabled and enforced for the `authorization_code` grant: a token request presenting a `code_verifier` that does not hash (SHA-256, base64url) to the `code_challenge` supplied at `/oauth2/authorize` time is rejected with `400 invalid_grant`, even if the authorization `code` itself is otherwise valid and unexpired. |
| NFR-19 | Access tokens issued by `/oauth2/token` carry an `aud` (audience) claim identifying the intended resource server(s) (RFC 8707) — e.g. the `mcp-server` module's registered resource identifier — so that a resource server can reject tokens not intended for it. This is required for `mcp-server`'s NFR-4 (see `docs/requirements/mcp-server.md`) to be satisfiable at all: if this API never emits an `aud` claim, no downstream audience check is possible. **⚠️ Known limitation, not exploitable today (pentest finding, 2026-09-21):** the as-implemented `jwtCustomizer` also unconditionally stamps this app's own `selfAudience` (`hello-world-api`) onto *every* token this Authorization Server issues, regardless of which client requested it. With exactly one registered OAuth client (`mcp-server`) in existence, this means the audience check on this app's own `/api/v1/hello` (NFR-19/`AudienceValidator`) is satisfied by construction for every token this AS instance ever issues — it currently provides **no real isolation between OAuth clients**. See `docs/pentest/mcp-oauth-pentest-report.md`, Finding 1, for the live reproduction. **If a second OAuth client/resource server is ever registered, this MUST be revisited** (RFC 8707 per-request resource scoping, or an explicit, written re-acceptance of the trade-off) before this check can be trusted as a real per-client boundary. |
| NFR-20 | The Authorization Server is implemented using **Spring Authorization Server** (or its capabilities as folded into Spring Security, whichever artifact the developer verifies compiles against this project's pinned Spring Boot 3.3.4 — see Handoff, §6) — not a hand-rolled `/oauth2/authorize` or `/oauth2/token` implementation, extending the NFR-11 principle to this new capability. Verifiable the same way as NFR-11: inspect the build file's dependency list; confirm no custom authorization-code store, no custom PKCE verifier, and no custom OAuth metadata endpoint hand-written from scratch. |

## 4. Out of Scope (flagged for improvement plan)
- Persistent database (demo uses in-memory store — swap for Postgres in production). This now also covers the Authorization Server's authorization-code and (if applicable) token/consent storage: in-memory only, not durable across restarts, consistent with the existing `UserStore` posture.
- Full OAuth2/social login, MFA, password-reset flow.
- Distributed/shared-state rate limiting across multiple instances (this
  revision requires a real rate-limiting *library*, e.g. Bucket4j, but it
  is still configured as an in-process/in-memory limiter; a
  Redis-backed distributed limiter remains a production improvement item).
- Migrating or deleting the prior hand-rolled Java implementation
  (`com.sun.net.httpserver` + hand-rolled JSON/JWT/PBKDF2/rate-limiter,
  see `docs/JAVA_PORT_NOTES.md`) is not specified here; that decision
  (retire vs. keep as a reference/benchmark) is left to the team.
- **Dynamic Client Registration (RFC 7591)** is explicitly out of scope for
  this revision. The MCP Authorization spec lists DCR support as a
  `SHOULD` (recommended), not a `MUST`, for MCP authorization servers —
  see the [MCP Authorization spec](https://modelcontextprotocol.io/specification/draft/basic/authorization)
  and RFC 7591 itself. A single pre-registered OAuth client (one
  `client_id`, a fixed `redirect_uri` set, `authorization_code` +
  `refresh_token` grants only) configured statically (e.g. an in-memory or
  properties-driven `RegisteredClientRepository`) is sufficient for
  `mcp-server` to act as that one client. Supporting additional/arbitrary
  OAuth clients via self-service registration is deferred to a future
  revision if/when a second MCP or OAuth client needs to be onboarded.
- Additional OAuth grant types (`client_credentials`, device code, implicit)
  are out of scope; only `authorization_code` (with mandatory PKCE) and
  `refresh_token` are required.
- A user-facing consent/scope-selection screen beyond the login form itself
  is out of scope for this revision (single pre-registered, implicitly
  trusted client; no third-party clients to consent to yet).

## 5. Assumptions
Judgment calls made where the product owner's directive named a category
of library but not a single specific product:

- **Password hashing algorithm:** NFR-1 has always said "bcrypt hashes,"
  even though the intervening hand-rolled Java port actually used PBKDF2.
  This revision assumes **Spring Security's `BCryptPasswordEncoder`** as
  the default, honoring the original NFR-1 wording. `Pbkdf2PasswordEncoder`
  is an acceptable substitute if the organization has a policy reason
  (e.g. FIPS compliance) to prefer PBKDF2 — either is "an established
  library," satisfying NFR-1 and NFR-11.
- **JWT library:** Recommend **`io.jsonwebtoken:jjwt`** (`jjwt-api` +
  `jjwt-impl` + `jjwt-jackson`) for HS256 signing/verification, since this
  API is both the token *issuer* and *verifier* for a single symmetric
  secret — a good fit for jjwt's simple `Jwts.builder()`/`Jwts.parser()`
  API. Nimbus JOSE+JWT is an acceptable alternative. Spring Security's
  OAuth2 Resource Server support is intentionally *not* mandated as the
  primary choice for the original JSON API's own tokens: it's designed for
  verifying tokens from an external issuer, and using it here as
  issuer-and-verifier would additionally require Spring Authorization
  Server or custom `JwtEncoder` wiring — more machinery than the plain
  JSON API needs on its own. (This calculus changes for the new OAuth
  Authorization Server capability, which explicitly does add that
  machinery — see NFR-20.) Whichever library is chosen for the original
  JSON API must satisfy FR-1, FR-2, FR-6, NFR-2, and NFR-3 unchanged.
- **Rate-limiting library:** Recommend **Bucket4j** (token-bucket,
  in-memory `ProxyManager`, easy per-key/per-endpoint configuration) as
  the primary choice for NFR-5. Resilience4j's `RateLimiter` is an
  acceptable alternative, particularly if the team already depends on
  Resilience4j elsewhere (e.g. circuit breakers).
- **Validation error status code:** Spring Boot's default handling of
  `@Valid` failures (`MethodArgumentNotValidException`) returns HTTP `400`,
  not the `422` required by NFR-7. Preserving NFR-7's existing behavior
  unchanged requires the developer to add an explicit
  `@ControllerAdvice`/`@ExceptionHandler` that maps validation failures to
  `422` with a field-level error body — flagged here so it isn't missed
  simply because it's "the framework default."
- **Spring Boot version pin:** "Spring Boot 3.x" is intentionally not
  pinned to an exact minor version; assume the latest stable Spring Boot
  3.x release available at implementation time that supports Java 21
  (Spring Boot 3.2+). The project is currently pinned to Spring Boot
  3.3.4 — the Authorization Server addition must be verified to compile
  and run against that exact pinned version (see Handoff, §6), not assumed
  compatible from documentation alone.
- **Dynamic Client Registration, single-client design, and the mcp-server
  tool-surface/Cloud-Run decisions** are recorded as Assumptions in
  `docs/requirements/mcp-server.md` §5, since they're driven primarily by
  that module's design — cross-referenced here rather than duplicated, with
  the exception of the DCR-out-of-scope citation above, which belongs to
  this API (the Authorization Server) directly.

## 6. Handoff to Developer
**Stack (mandatory):** **Spring Boot 3.x + Java 21**, pinned to 3.3.4. The
zero-runtime-dependency posture of the earlier hand-rolled Java port (see
`docs/JAVA_PORT_NOTES.md`) is explicitly superseded by this directive —
Maven Central is reachable from this environment, and "small enough to
audit" is no longer an acceptable reason to hand-roll a security-critical
or cross-cutting primitive. For each concern currently hand-rolled, use the
following (or a documented equivalent per §5 Assumptions), matching the
FR/NFR each satisfies:

| Concern | Hand-rolled today | Required library | Satisfies |
|---|---|---|---|
| Web/HTTP layer | `com.sun.net.httpserver` | `spring-boot-starter-web` | FR-1..FR-7 |
| JSON parsing/serialization | Hand-rolled JSON parser | **Jackson** (ships with `spring-boot-starter-web`) | FR-3, FR-4, FR-5, FR-6, NFR-7, NFR-11 |
| JWT issuance/verification (JSON API) | Hand-rolled HS256 (`javax.crypto.Mac`) | **`io.jsonwebtoken:jjwt`** (or Nimbus JOSE+JWT — see Assumptions) | FR-1, FR-2, FR-6, NFR-2, NFR-3, NFR-11 |
| Password hashing | Hand-rolled PBKDF2 | **Spring Security `PasswordEncoder`** (`BCryptPasswordEncoder`, or `Pbkdf2PasswordEncoder` per Assumptions) | FR-4, NFR-1, NFR-11 |
| Rate limiting | Hand-rolled sliding window (`RateLimiter.java`) | **Bucket4j** (or Resilience4j `RateLimiter` — see Assumptions) | NFR-5, NFR-11 |
| Request validation | Manual field checks | **Jakarta Bean Validation** via `spring-boot-starter-validation` | NFR-7, NFR-11 |
| Security headers / CORS | Hand-written | **Spring Security** default header filters + CORS config | NFR-6, NFR-8 |
| Secrets/config | `Config.java` env loader | Spring Boot's externalized configuration (`application.yml` + env vars); same "fail fast if `JWT_SECRET_KEY` is missing/short" behavior | NFR-2 |
| **OAuth 2.1 Authorization Server (new)** | N/A — new capability | **Spring Authorization Server** (`org.springframework.security:spring-authorization-server`, or the equivalent artifact if/when its capabilities have been folded into core Spring Security — verify exact current coordinates/version by compiling against this project's pinned Spring Boot 3.3.4, per the same "verify empirically, don't assume" discipline used elsewhere in this repo) | NFR-13..NFR-20 |
| Tests | JUnit 5 (hand-run HTTP client) | JUnit 5 + `spring-boot-starter-test` (`MockMvc` or `@SpringBootTest` with `TestRestTemplate`) | verifies all FR/NFR above |

**Two integration traps to flag explicitly for the Authorization Server work:**

1. **Bridge, don't duplicate, `UserStore`.** `UserStore` (see
   `src/main/java/com/apitest/store/UserStore.java`) is a plain
   `ConcurrentHashMap`, *not* a Spring Security `UserDetailsService`. The
   `/oauth2/authorize` login form must authenticate against this same store
   (NFR-17) — write a `UserDetailsService` adapter that wraps `UserStore`
   and reuses the existing `PasswordEncoder` bean for the credential check,
   rather than standing up a second, disconnected set of Spring
   Security-managed users. If a developer configures Spring Security's
   default in-memory `UserDetailsManager` (e.g. via
   `InMemoryUserDetailsManager` with its own hardcoded/test users) instead
   of bridging to `UserStore`, NFR-17 fails even though the login form
   "works."
2. **Audience (`aud`) claim is opt-in, not automatic.** Spring
   Authorization Server does not, by default, restrict which resource
   server(s) an issued access token is valid for unless explicitly
   configured to embed and scope an `aud` claim (RFC 8707) per client/
   resource registration. NFR-19 requires this explicitly because
   `mcp-server`'s audience-validation requirement (its NFR-4, in
   `docs/requirements/mcp-server.md`) is unenforceable if this API never
   emits a distinguishing `aud` claim in the first place — this is the
   single most common way this class of MCP/OAuth integration gets built
   incompletely, so treat it as a first-class requirement, not an
   afterthought.

No new functional behavior is authorized beyond what NFR-12..NFR-20
specify: FR-1..FR-7 and NFR-1..NFR-10's endpoints, request/response bodies,
status codes, token lifetimes, and error-handling semantics must match the
existing, previously reviewed behavior exactly.
