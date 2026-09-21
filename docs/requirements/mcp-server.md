# Technical Requirements — Hello World MCP Server

**Author:** BA role · **Input:** Product owner directive to (a) formalize
requirements for the `mcp-server/` module built in PR #4 (which was built
directly, without going through this repo's usual ba → developer → qa →
pentester → reviewer pipeline), and (b) change its architecture so it
authenticates as a proper OAuth 2.1 Resource Server instead of accepting
raw usernames/passwords/tokens as LLM-visible tool arguments.

This is the first formal requirements document for `mcp-server`. It
captures both what the module already does (as built in PR #4, treated
below as an existing, already-implemented baseline) and the new OAuth
resource-server behavior and tool-surface changes this revision requires.
This document becomes the baseline QA, pentesting, and review will check
future `mcp-server` changes against.

## 1. Scope

`mcp-server` is a separate Spring Boot 4.1.0 / Java 21 application that
exposes the `hello-world-api` REST API (see
`docs/requirements/hello-world-api.md`) as [MCP](https://modelcontextprotocol.io)
tools an AI agent can call directly in conversation, over a stateless
Streamable-HTTP transport, instead of a developer writing HTTP client code
against `hello-world-api` themselves. It is a thin translation layer — it
holds no independent business logic or user data of its own.

In scope for this revision:
- Documenting the existing tool surface, transport, and deployment as
  already built (FR-1, FR-2, FR-3, FR-9 below).
- Making `mcp-server` an OAuth 2.1 Resource Server per the
  [MCP Authorization spec](https://modelcontextprotocol.io/specification/draft/basic/authorization),
  validating access tokens issued by `hello-world-api`'s new Authorization
  Server (FR-4, FR-5, FR-6, FR-7, FR-8, and the NFRs in §3).
- Removing/changing tools whose arguments currently carry raw credentials
  or bearer tokens, so that these values no longer pass through the
  calling LLM's own context/conversation/logs.
- Recording explicit product decisions on `register_user`'s tool-argument
  design, the fate of `refresh_access_token`, and the Cloud Run IAM gate
  (§5 Assumptions).

Out of scope: any change to `hello-world-api`'s own REST behavior (that's
`docs/requirements/hello-world-api.md`'s concern); Dynamic Client
Registration (see that same document, §4); any new tool beyond the four
addressed here; persistent storage of anything in `mcp-server` itself
(it remains stateless and holds no secrets of its own beyond its OAuth
resource-server configuration).

## 2. Functional Requirements

**Existing behavior (built in PR #4, unchanged by this revision unless noted):**

| ID | Requirement |
|----|-------------|
| FR-1 | `mcp-server` exposes a stateless Streamable-HTTP JSON-RPC MCP endpoint at `POST /mcp` (Spring AI MCP Server Boot Starter, `spring.ai.mcp.server.protocol: STATELESS`, `type: SYNC`), responding to standard MCP methods including `tools/list` and `tools/call`. |
| FR-2 | The `check_api_health` tool takes no arguments, calls `GET <api.base-url>/health` on `hello-world-api`, and returns that response's JSON body verbatim on any `2xx`, or `{"http_status": <code>, "error": "..."}` on a non-2xx response — never an opaque MCP protocol error. |
| FR-3 | The `register_user` tool takes `username` and `password` string arguments, calls `POST /api/v1/auth/register` on `hello-world-api`, and returns that response's body (success) or the `{"http_status", "error"}` shape (failure), unchanged by this revision — see Assumption 1 (§5) for why. |
| FR-9 | `mcp-server` is built as an independent Maven module (`mcp-server/`, its own `pom.xml`, not a submodule of `hello-world-api`'s build), packaged into a container image via `mcp-server/Dockerfile`, and deployed to its own Cloud Run service (`hello-world-mcp-server`) via a path-filtered GitHub Actions workflow (`mcp-ci-cd.yml`, triggered only on changes under `mcp-server/**`), independent of `hello-world-api`'s deployment. |

**Revised behavior (this revision):**

| ID | Requirement |
|----|-------------|
| FR-4 | The `login` tool is **removed**. Authentication instead happens via the OAuth 2.1 `authorization_code` + PKCE browser-redirect flow, initiated by the MCP client at connection time against `hello-world-api`'s `/oauth2/authorize` and `/oauth2/token` endpoints (see `docs/requirements/hello-world-api.md`), entirely outside the LLM's visible conversation/tool-call context. |
| FR-5 | The `get_hello_greeting` tool takes **no LLM-visible token argument**. It reads the caller's identity from the authenticated request's security context (e.g. an injected `Jwt` via `@AuthenticationPrincipal Jwt` or `SecurityContextHolder`, established by Spring Security's resource-server filter chain before the tool method body runs) and calls `GET /api/v1/hello` on `hello-world-api` using that token as the `Authorization: Bearer` header, returning the response body or the `{"http_status", "error"}` shape. A `tools/call` for `get_hello_greeting` that includes any parameter resembling a token/credential is rejected by the tool's input schema (no such parameter exists). |
| FR-6 | The `refresh_access_token` tool is **removed** (see Assumption 2, §5). Token refresh is handled by the MCP client library itself via the standard OAuth 2.1 `refresh_token` grant against `hello-world-api`'s `/oauth2/token`, without any LLM-visible tool call. |
| FR-7 | A `POST /mcp` request whose `Authorization` header is missing, malformed, or carries a token that fails resource-server validation (expired, bad signature, wrong issuer, or wrong audience — see NFR-1..NFR-5) receives an HTTP `401`, with the `WWW-Authenticate` header populated per NFR-3 — not a bare MCP-level JSON-RPC error with no recovery information. `check_api_health` and `register_user` remain callable without any `Authorization` header (they do not require an authenticated principal). |
| FR-8 | `GET /.well-known/oauth-protected-resource` returns an unauthenticated `200` with an RFC 9728 Protected Resource Metadata JSON document, including at minimum a `resource` identifier for `mcp-server` and an `authorization_servers` array naming `hello-world-api`'s issuer URL. |

## 3. Non-Functional / Security Requirements

| ID | Requirement |
|----|-------------|
| NFR-1 | `mcp-server` validates OAuth access tokens using Spring Security's OAuth2 Resource Server support (`spring-boot-starter-oauth2-resource-server`, `JwtDecoder` configured via `hello-world-api`'s JWK Set URI / issuer-uri) — not hand-rolled JWT parsing/verification code, matching the "no hand-rolled security-critical primitives" precedent already established in `hello-world-api`'s NFR-11. Verifiable by inspecting `mcp-server/pom.xml` for the dependency and confirming no custom JWT signature-verification code exists in `mcp-server`'s source. |
| NFR-2 | `mcp-server` rejects any token not signed by `hello-world-api`'s configured Authorization Server (wrong issuer, self-signed, or signed by an unrelated key) with `401`. Test: a syntactically valid JWT signed with an arbitrary/unknown key is rejected. |
| NFR-3 | Every `401` response from `mcp-server`'s resource-server filter chain includes a `WWW-Authenticate` header pointing at `mcp-server`'s own `/.well-known/oauth-protected-resource` URL, per RFC 9728 §5.1, so a compliant MCP client can discover how to obtain a valid token without prior out-of-band knowledge. |
| NFR-4 | `mcp-server` validates the token's `aud` (audience) claim names `mcp-server` specifically (RFC 8707) via an explicit custom `OAuth2TokenValidator<Jwt>` bean, and rejects tokens whose audience is absent or names a different resource, with `401`. **This does not happen by default** — Spring's out-of-the-box resource-server configuration validates signature, issuer, and expiry, but not audience, so omitting this bean silently accepts tokens meant for other resource servers. This is called out as the single most common way this class of MCP/OAuth integration is built incompletely; QA must have a dedicated test: a validly-signed token issued by the correct authorization server, with a well-formed but *different* `aud` value, must be rejected. |
| NFR-5 | `mcp-server` never accepts a raw password or access/refresh token as an MCP tool argument for any operation that authenticates an *existing* session (i.e. `login` and `get_hello_greeting`'s prior token argument are gone, per FR-4/FR-5) — closing the original PR #4 finding that such values pass through the calling LLM's own context and logs, not just the MCP server's. |
| NFR-6 | `mcp-server` never logs the `Authorization` header, raw JWT contents, or any tool argument value that is a password (i.e. `register_user`'s `password` argument), at any log level, extending `hello-world-api`'s NFR-9 practice into this module. |
| NFR-7 | `check_api_health` and `register_user` remain reachable without a Bearer token (no regression from PR #4's behavior); all other tools require a valid, audience-scoped access token per NFR-1..NFR-4. |
| NFR-8 | The Cloud Run IAM invocation gate (`--allow-unauthenticated` vs. requiring a GCP identity token) for the `hello-world-mcp-server` service is set per the explicit decision recorded in Assumption 3 (§5), not left as whatever PR #4 happened to configure without re-evaluation. |
| NFR-9 | Dependency and static-security scanning (matching `hello-world-api`'s NFR-10 practice) is run on `mcp-server` before release, now covering the added OAuth2 resource-server dependency tree. |

## 4. Out of Scope (flagged for improvement plan)
- Dynamic Client Registration (RFC 7591) — see
  `docs/requirements/hello-world-api.md` §4 for the citation and reasoning;
  `mcp-server` is the single pre-registered OAuth client for this
  revision, with a static `client_id`/`redirect_uri` configuration.
- Persistent session or token storage inside `mcp-server` itself — it
  remains fully stateless (`STATELESS` MCP protocol mode); nothing about
  the OAuth resource-server addition changes that.
- Support for authorization servers other than `hello-world-api` (i.e.
  multi-issuer trust) — out of scope; NFR-2 explicitly requires rejecting
  tokens from any other issuer.
- A UI or dashboard for humans to inspect `mcp-server`'s own logs/health
  beyond the existing `check_api_health` tool and Cloud Run's own logging.
- Rate limiting on `mcp-server`'s own `/mcp` endpoint independent of
  `hello-world-api`'s existing `/auth/*` rate limiting — not specified
  here; flagged as a potential future improvement item, since a
  resource-server 401 does not, by itself, throttle repeated invalid-token
  attempts.

## 5. Assumptions

Three consequential decisions the business ask left open, recorded
explicitly per this role's process rather than guessed silently:

1. **Should `register_user` (username + password as LLM-visible tool
   arguments) also move out of the tool-argument path, for full
   consistency with `login`/`get_hello_greeting`?**
   **Decision: No — keep `register_user` as-is, with `username` and
   `password` as tool arguments (FR-3).**
   **Reasoning:** Creating a *new* account is a materially lower-risk
   operation than authenticating into an *existing* one: a password
   chosen and submitted for a brand-new registration has no prior value
   to protect (it isn't yet a live credential guarding an account with
   history/data), and a leaked value from this call can only be used to
   "hijack" the account the *same actor* just created, not someone else's.
   Additionally, OAuth 2.1 has no standard "signup" step to redirect the
   user through — `/oauth2/authorize` presupposes an account already
   exists — so there's no equivalent OAuth-native flow to move
   registration into the way there is for login. This is a judgment call,
   not a hard requirement of the MCP or OAuth specs; if the product owner
   later decides even new-account passwords should never transit LLM
   context, `register_user` should be reworked as a request that returns a
   one-time web-based registration link instead. Flagging here so it is a
   visible, revisitable decision rather than a silent omission.

2. **Does `refresh_access_token` still need to be an LLM-facing tool once
   real OAuth token refresh is handled by the MCP client library?**
   **Decision: Remove it (FR-6).**
   **Reasoning:** Once `mcp-server` is a real OAuth 2.1 resource server and
   authentication happens via the standard authorization_code + PKCE
   browser flow at connection time, the standard `refresh_token` grant
   (RFC 6749 §6) against `hello-world-api`'s `/oauth2/token` is the
   MCP/OAuth-spec-defined mechanism for renewing an access token, and
   compliant MCP client libraries are expected to perform it automatically
   and transparently, without LLM involvement — the whole point of moving
   auth to the connection level is that the LLM shouldn't need to reason
   about tokens at all. Keeping a `refresh_access_token` tool around would
   reintroduce exactly the kind of LLM-visible token handling this
   revision is meant to eliminate, for no remaining benefit.

3. **Does the Cloud Run IAM gate (`--allow-unauthenticated` withheld,
   requiring a GCP identity token) still add meaningful defense-in-depth
   once `mcp-server` does real per-end-user OAuth 2.1 authentication, or
   should it be removed in favor of the OAuth layer alone?**
   **Decision (confirmed by product owner 2026-09-21): move to
   `--allow-unauthenticated`, making the OAuth 2.1 resource-server check
   the sole authorization boundary at the application layer.**
   **Reasoning:**
   - The GCP IAM gate in PR #4 was explicitly compensating for the *lack*
     of real per-end-user authentication (raw credentials as tool
     arguments, no token verification of any kind at the transport). That
     gap is what this revision closes; the original rationale for the
     GCP-account-level gate no longer applies once every `/mcp` request is
     independently authenticated per end user via a validated,
     audience-scoped Bearer token.
   - More importantly, **interoperability**: standard, off-the-shelf MCP
     clients (the kind this OAuth work is meant to support) know how to
     perform the MCP/OAuth 2.1 browser-redirect flow and attach the
     resulting Bearer token — they do not know how to additionally mint
     and attach a GCP identity token as a second, GCP-specific credential.
     Keeping the IAM gate would make `hello-world-mcp-server` unreachable
     by any standard MCP client, defeating the purpose of implementing
     the standard OAuth flow in the first place, and would leave the
     module usable only via bespoke tooling that knows to mint a GCP
     token (exactly the friction this revision is meant to remove).
   - This is a legitimate architectural tradeoff, not a clear-cut
     technical requirement — stacking the GCP IAM gate and OAuth *does*
     technically provide two independent boundaries, and a security
     reviewer could reasonably prefer defense-in-depth over
     interoperability with generic clients if `mcp-server` is only ever
     going to be called by an internal, GCP-identity-aware client anyway.
     The product owner weighed this and confirmed the interoperability
     argument wins for this project. The developer must update
     `mcp-server/README.md` and `docs/deploy/mcp-server-setup.md` (both
     currently describe and justify the IAM-gated posture) to match.

## 6. Handoff to Developer

**Stack (mandatory):** Spring Security's OAuth2 Resource Server support
(`spring-boot-starter-oauth2-resource-server`), configured with a
`JwtDecoder` pointed at `hello-world-api`'s JWK Set URI (or issuer-uri, if
using issuer-based auto-discovery against `/.well-known/oauth-authorization-server`)
— not hand-rolled JWT/token verification, matching this repo's established
"no hand-rolled security-critical primitives" precedent (`hello-world-api`
NFR-11, extended here as NFR-1).

| Concern | Required library | Satisfies |
|---|---|---|
| OAuth 2.1 resource-server token validation | **`spring-boot-starter-oauth2-resource-server`**, `JwtDecoder` via JWK Set URI | NFR-1, NFR-2, FR-4..FR-7 |
| Audience (`aud`) validation | Custom `OAuth2TokenValidator<Jwt>` bean, composed with the default issuer/signature/expiry validators via `DelegatingOAuth2TokenValidator` | NFR-4 |
| Protected Resource Metadata (RFC 9728) | A simple `@RestController` endpoint (no library mandates a specific implementation here; Spring Security does not ship this out of the box as of this writing — verify empirically at implementation time whether a newer Spring Security release adds first-class support before hand-writing it) | FR-8 |
| `WWW-Authenticate` header on 401 | Custom `AuthenticationEntryPoint` bean wired into the resource-server filter chain | NFR-3, FR-7 |

**Two integration traps to flag explicitly (mirrored in
`docs/requirements/hello-world-api.md` §6, since both sides matter for
this to work end to end):**

1. **Audience validation is not automatic.** Spring's default
   resource-server configuration validates token signature, issuer, and
   expiry — it does **not** validate the `aud` claim unless an explicit
   custom `OAuth2TokenValidator<Jwt>` is added and composed in. This is,
   per the product owner's own framing, the single most common way this
   category of MCP/OAuth integration gets built incompletely. NFR-4 exists
   specifically so this isn't missed, and QA's baseline test suite for
   this module must include the "differently-audienced but validly-signed
   token is rejected" test called out there.
2. **The credential source is `hello-world-api`'s `UserStore`, bridged via
   a `UserDetailsService` adapter — not a new set of users.** This is
   primarily a `hello-world-api`-side concern (see that document's Handoff,
   §6, trap 1), but `mcp-server`'s developer should be aware of it too: if
   the Authorization Server's login form is ever backed by a different set
   of users than `hello-world-api`'s own `/api/v1/auth/*` endpoints, an
   MCP end user's OAuth login and their direct API credentials will
   silently diverge, defeating FR-3's "same backend, same users" premise
   for the whole integration.

Also verify at implementation time: `mcp-server` is currently pinned to
**Spring Boot 4.1.0**, while `hello-world-api` (the Authorization Server)
is pinned to **Spring Boot 3.3.4** — these are two independent Maven
modules/deployables, so this mismatch is not itself a blocker, but the
developer should confirm the chosen `spring-boot-starter-oauth2-resource-server`
version on the `mcp-server` (Boot 4.1.0) side interoperates correctly with
tokens/metadata produced by Spring Authorization Server running under Boot
3.3.4 on the `hello-world-api` side — verify by integration-testing the two
services together, not by assuming version compatibility from
documentation alone (the same "verify empirically" discipline this repo
has applied to prior library-syntax questions).
