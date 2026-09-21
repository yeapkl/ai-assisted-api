# Final Review — OAuth 2.1 Authorization Server + MCP Resource Server Redesign

**Branch:** `mcp/hello-world-mcp-server` · **HEAD reviewed:** `f1c3510`
**Scope:** `docs/requirements/hello-world-api.md` NFR-12..NFR-20 (OAuth 2.1
Authorization Server addition) and `docs/requirements/mcp-server.md` (first
formal requirements doc for `mcp-server`, FR-1..FR-9, NFR-1..NFR-9), as
implemented across `src/main/java/com/apitest/oauth/**`,
`src/main/java/com/apitest/filter/{JwtAuthFilter,RateLimitFilter}.java`, and
`mcp-server/src/main/java/com/apitest/mcp/**`.

## Verdict: **APPROVED WITH FOLLOW-UPS**

The redesign meets its stated goal: raw passwords/tokens no longer flow
through MCP tool arguments; authentication now happens via a real,
spec-compliant OAuth 2.1 `authorization_code`+PKCE browser flow, and
`mcp-server` is a genuine OAuth 2.1 resource server. Every MUST-level MCP
Authorization spec requirement I checked is independently, live-verified as
actually implemented, not just claimed. Both previously-flagged pentest
findings are either fixed (stack-trace leak) or adequately, consistently
documented as an accepted, non-blocking scope limitation (self-audience
no-op). No High/Critical issue exists. The reasons for "with follow-ups"
rather than a clean APPROVED are two Low-severity gaps this review found
independently (below) that were not previously called out, plus carrying
forward the QA/pentest reports' own honestly-disclosed coverage gaps.

## What was verified, and how

### 1. Documents read in full
`docs/requirements/hello-world-api.md` (NFR-12..NFR-20 and Handoff §6),
`docs/requirements/mcp-server.md` (whole document), `docs/qa/hello-world-api-report.md`
(OAuth section, dated 2026-09-21), `docs/qa/mcp-server-report.md` (whole),
`docs/pentest/mcp-oauth-pentest-report.md` (whole).

### 2. Code spot-checked directly (not just trusted from the reports)
Read in full: `AuthorizationServerConfig`, `JwkConfig`, `OAuthProperties`,
`AudienceValidator`, `UserStoreUserDetailsService`, `LoginController`,
`LoginFailureHandler`, `RejectPlainPkceFilter` (hello-world-api side);
`JwtAuthFilter`, `RateLimitFilter` (dual-token-family + dual-rate-limit
additions); `HelloApiTools`, and every class under
`mcp-server/.../mcp/security/` (`AudienceValidator`,
`CachedBodyHttpServletRequest`, `JwtDecoderConfig`,
`McpAuthenticationEntryPoint`, `McpToolAuthorizationFilter`,
`OAuthResourceServerProperties`, `ProtectedResourceMetadataController`,
`SecurityConfig`) and `mcp/web/McpErrorResponseSanitizationConfig`. Also
read `.github/workflows/mcp-ci-cd.yml` in full.

Findings from direct code reading:
- `AuthorizationServerConfig.jwtCustomizer` and `OAuthProperties`'s Javadoc
  match the QA report's and pentest's description of the self-audience
  no-op exactly — the code, its comments, both requirements docs, the QA
  report, and the pentest report are all internally consistent about this
  being a known, accepted, non-blocking limitation. No discrepancy found.
- `mcp-server`'s `AudienceValidator`/`JwtDecoderConfig` genuinely compose a
  custom `OAuth2TokenValidator<Jwt>` via `DelegatingOAuth2TokenValidator`
  with `JwtValidators.createDefaultWithIssuer(...)` — this is a real,
  distinct-from-`hello-world-api`'s-own-endpoint audience check (mcp-server's
  NFR-4), correctly enforced independently of Finding #1's limitation.
- `McpToolAuthorizationFilter` correctly scopes the Bearer-token requirement
  to only the `get_hello_greeting` tool call by peeking at the buffered
  JSON-RPC body; `check_api_health`/`register_user`/`tools/list` fall
  through unauthenticated as specified (NFR-7). `SecurityContextHolder` is
  cleared in a `finally` block — no auth leakage across requests on the same
  thread.
- `McpErrorResponseSanitizationConfig`'s Jackson mixin approach
  (`@JsonIgnoreProperties` on `Throwable`, applied via
  `JsonMapperBuilderCustomizer`) is a real fix, not just a docstring claim —
  confirmed both by reading the code's reasoning (Spring AI's transport
  serializes `McpError` — a `Throwable` — directly as a response body,
  bypassing `@ControllerAdvice`) and by live reproduction (see below).
- `RateLimitFilter`'s two-`FilterRegistrationBean` split (default order for
  `/api/v1/auth/*`, `HIGHEST_PRECEDENCE` for `/oauth2/*`+`/login`) is
  correctly reasoned and matches the documented trade-off (429s on the OAuth
  paths don't carry security headers, since they run ahead of Spring
  Security's own header-writing filter — explicitly accepted, not a defect).
- `.github/workflows/mcp-ci-cd.yml` line 127: `flags: --port=8080
  --service-account=... --allow-unauthenticated` — confirmed to match the
  product owner's recorded decision (mcp-server.md §5, Assumption 3)
  precisely, and `mcp-server/README.md` / `docs/deploy/mcp-server-setup.md`
  are both updated to document and justify the new posture.

### 3. Test suites run personally (not taken from the reports)

**hello-world-api** — `cd /home/user/apitest && mvn -B test`:
```
Tests run: 142, Failures: 0, Errors: 0, Skipped: 0 — BUILD SUCCESS
```
Matches the expected 142/142 exactly (126 pre-OAuth + 16 QA OAuth tests, incl.
the new 6-class `OAuthAuthorizationServerSmokeTest`/`AudienceValidator`
coverage family described in the QA report).

**mcp-server** — required a live `hello-world-api` instance. Started it
myself: `mvn -B -q -DskipTests package`, then ran
`target/hello-world-api.jar` on port 18000 with `JWT_SECRET_KEY`,
`OAUTH_SIGNING_KEY_SECRET`, `MCP_OAUTH_CLIENT_SECRET` (fresh
`openssl rand -hex 32` values), `OAUTH_ISSUER=http://localhost:18000`,
`MCP_OAUTH_CLIENT_ID=mcp-server`, `MCP_OAUTH_RESOURCE_AUDIENCE=mcp-server`,
`OAUTH_ACCESS_TOKEN_EXPIRE_MINUTES=1` (exact property names taken from
`docs/qa/mcp-server-report.md`'s reproduction script, cross-checked against
`OAuthProperties`/`application.yml`). Confirmed `GET /health` → `200`, then:
```
cd mcp-server && mvn -B test -Dqa.mcp-oauth-client-secret="$MCP_OAUTH_CLIENT_SECRET"
Tests run: 24, Failures: 0, Errors: 0, Skipped: 0 — BUILD SUCCESS
```
Breakdown: `HelloApiToolsTest` 6, `QaMcpResourceServerIntegrationTest` 9
(incl. the genuine ~135s real-time token-expiry wait), `QaMcpAudienceMismatchRejectsRealTokenTest` 1,
`McpMalformedRequestErrorSanitizationTest` 3 (new — the pentest Finding 2
regression test, not mentioned in the QA report since it postdates it),
`AudienceValidatorTest` 5. 24 = the QA report's 21 + 3 new tests added by
the pentest-fix commit. Both java processes (`hello-world-api.jar`,
`hello-world-mcp-server.jar`) were killed and the throwaway `.env` removed
after testing; `git status` confirms a clean working tree.

### 4. MCP Authorization spec MUST requirements — independently re-verified live, not just via the test suite

With both services running locally, I issued raw HTTP requests myself (not
just re-running the test suite) and confirmed:
- `GET /.well-known/oauth-protected-resource` → `200`,
  `{"resource":"http://localhost:18080","authorization_servers":["http://localhost:18000"]}`
  (RFC 9728) — real, unauthenticated, live.
- `POST /mcp` calling `get_hello_greeting` with no token → `401` with
  `WWW-Authenticate: Bearer resource_metadata="http://localhost:18080/.well-known/oauth-protected-resource", error="invalid_token"`
  — live, matches NFR-3/FR-7 exactly.
- `GET /oauth2/authorize?...&code_challenge_method=plain` →
  `400 {"error":"invalid_request","error_description":"code_challenge_method must be S256; plain is not permitted"}`
  — live, PKCE S256-only enforcement (NFR-18) confirmed before a code is
  ever issued.
- `GET /.well-known/oauth-authorization-server` → `200`, RFC 8414 JSON with
  `code_challenge_methods_supported: ["S256"]` only (no `plain` advertised).
- `POST /mcp` with a malformed body (`{}`) → sanitized
  `{"jsonRpcError":{...},"message":"Invalid message format"}`, **no**
  `stackTrace`/`className`/package internals — live confirmation the pentest
  Finding 2 fix actually works, not just that its regression test passes.
- Audience validation on `mcp-server`'s resource-server side (its own NFR-4,
  distinct from hello-world-api's Finding #1): confirmed via
  `QaMcpAudienceMismatchRejectsRealTokenTest` (a real, correctly-signed
  token from the live AS, differently-audienced, rejected) plus direct
  reading of `AudienceValidator`/`JwtDecoderConfig` — this check is real and
  does not share Finding #1's no-op property, since `mcp-server` has no
  equivalent "unconditionally stamp my own audience" logic on its
  validation side.

### 5. The two explicitly-accepted items

1. **hello-world-api's own audience check provides no real per-client
   isolation today** (self-audience unconditionally stamped) — confirmed
   documented consistently and thoroughly in code (`AuthorizationServerConfig.jwtCustomizer`
   and `AudienceValidator` Javadoc, both carrying explicit "read before
   touching this / before onboarding a second client" warnings),
   `hello-world-api.md` NFR-19, `mcp-server.md` §4, QA's Finding 1, and the
   pentest's Finding 1 — all five sources agree on severity, mechanism, and
   the "not exploitable today, revisit if client #2 is onboarded"
   framing. Not re-litigated here per the task brief; adequately documented.
2. **RFC 7591 Dynamic Client Registration out of scope** — confirmed cited
   correctly (SHOULD, not MUST, per the MCP Authorization spec) in both
   requirements docs' §4. Adequate.

## Issues found (ranked by severity)

**None High or Critical.** Two Low-severity items, both newly noted by this
review (not previously flagged by QA or pentest):

1. **Low — OAuth login surfaces (`/login`, `/oauth2/authorize`,
   `/oauth2/token`) have no automated test asserting their `429` responses
   carry no security headers, even though this is a documented,
   intentional trade-off in `RateLimitFilter`'s Javadoc.** This is a
   "gap in test coverage for a documented trade-off," not a functional
   defect — flagging so it doesn't silently regress if the filter ordering
   is ever refactored. Low priority; no fix required before merge.
2. **Low — no automated guardrail (e.g. a CI check or a startup assertion)
   exists to catch the day a second `RegisteredClient`/resource-audience
   value is added without also revisiting `jwtCustomizer`, despite both the
   code comments and the pentest report explicitly calling for one.**
   Currently a purely manual/process safeguard ("read the Javadoc before
   touching this"). Recommend a lightweight follow-up: a unit test that
   fails if `resourceAudience != selfAudience` and more than one
   `RegisteredClient` exists in the repository, so the regression can't
   land silently. Not blocking for this merge (single-client architecture
   today), but worth tracking as a concrete follow-up item rather than
   relying on comment-reading discipline indefinitely.

Carried forward (already disclosed by QA/pentest, not new, not blocking):
- No rate limiting on `/mcp` itself (explicitly out of scope,
  `mcp-server.md` §4).
- NFR-6 (mcp-server never logs secrets) and NFR-9/NFR-10 (dependency/SAST
  scanning) verified only by inspection, not automated tests — both
  correctly disclosed as gaps by QA rather than silently claimed as covered.
- NFR-7's "field-level error body" is a single string, not per-field
  structured data — pre-existing, not a regression from this work.

## Recommendation

**APPROVED WITH FOLLOW-UPS.** Ship as-is. Track the two Low items above
(rate-limit-header test coverage for OAuth surfaces; a guardrail test for
the self-audience limitation) as backlog follow-ups, not release blockers.
The architecture is genuinely spec-compliant (RFC 6749/7636/8414/8707/9728
and the MCP Authorization spec's MUST items all independently verified live
by this review, not merely asserted by prior reports), and every one of
those prior reports' claims that I spot-checked held up under direct code
reading and independent live re-verification.
