# QA Verification Report — Hello World MCP Server

**This is the first formal QA report for `mcp-server`** (per
`docs/requirements/mcp-server.md`, the module's first formal requirements
document — PR #4 built the module directly, without going through this
repo's usual ba → developer → qa → pentester → reviewer pipeline). This
report covers that requirements doc in full: the existing/baseline
behavior (FR-1, FR-2, FR-3, FR-9) and the new OAuth 2.1 resource-server
revision (FR-4..FR-8, NFR-1..NFR-9).

## Verdict: **PASS**

All FR/NFR items with a defined, testable behavior passed independent,
real-HTTP verification — including a full end-to-end integration test
against a genuinely running `hello-world-api` instance (real OAuth
authorization_code+PKCE flow, real signed tokens, real call-through for the
greeting), not mocks. Two items have no automated test and are called out
as gaps (NFR-6, NFR-9) rather than silently skipped, per this role's
standard. No blocking defects were found in `mcp-server` itself. See
"Findings requiring hello-world-api-side fixes" below for two real,
confirmed findings that live on the `hello-world-api` side of this
integration (JwtAuthFilter's audience blindness, and the public-client
refresh-token behavior) — both are written up in
`docs/qa/hello-world-api-report.md` since that's the module whose code
would change, not `mcp-server`'s.

## How to reproduce this run

This suite requires a **real, separately running `hello-world-api`**
instance (not mocked) — the whole point of the end-to-end tests. Exact
commands used for this QA pass:

```bash
# 1. Build and package hello-world-api (from repo root)
cd /home/user/apitest
mvn -o -q -DskipTests package

# 2. Generate throwaway secrets and start hello-world-api as a real
#    background process on port 18000, with the OAuth Authorization Server
#    enabled, aud stamped as "mcp-server", and a short (1-minute) access
#    token TTL so the real-time expiry test doesn't require a 15-minute wait.
JWT_SECRET_KEY=$(openssl rand -hex 32)
OAUTH_SIGNING_KEY_SECRET=$(openssl rand -hex 32)
MCP_OAUTH_CLIENT_SECRET=$(openssl rand -hex 32)
OAUTH_ISSUER=http://localhost:18000 \
MCP_OAUTH_CLIENT_ID=mcp-server \
MCP_OAUTH_REDIRECT_URIS=http://127.0.0.1:8765/callback \
MCP_OAUTH_RESOURCE_AUDIENCE=mcp-server \
OAUTH_ACCESS_TOKEN_EXPIRE_MINUTES=1 \
PORT=18000 \
APP_ENV=development \
JWT_SECRET_KEY="$JWT_SECRET_KEY" \
OAUTH_SIGNING_KEY_SECRET="$OAUTH_SIGNING_KEY_SECRET" \
MCP_OAUTH_CLIENT_SECRET="$MCP_OAUTH_CLIENT_SECRET" \
java -jar target/hello-world-api.jar &

# wait for it to come up, then confirm:
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:18000/health   # expect 200

# 3. Run the mcp-server suite against it (from mcp-server/), passing the
#    same client secret so the test can complete the token exchange:
cd mcp-server
mvn -o test -Dqa.mcp-oauth-client-secret="$MCP_OAUTH_CLIENT_SECRET"
```

**Result on this run:** `Tests run: 21, Failures: 0, Errors: 0, Skipped: 0`
— `BUILD SUCCESS`. Per-class breakdown:

```
HelloApiToolsTest                          : 6  passed  (developer's own suite, unmodified)
QaMcpResourceServerIntegrationTest         : 9  passed  (new, real end-to-end, ~134s — includes a genuine 130s real-time token-expiry wait)
QaMcpAudienceMismatchRejectsRealTokenTest  : 1  passed  (new, real end-to-end)
AudienceValidatorTest                      : 5  passed  (new, isolated unit test)
```

The one slow test (`nfr_expiredToken_realTimeExpiry_rejectedWith401`, ~130s
real wall-clock wait) is by design — see "Notes" below for why it can't be
avoided without weakening the assertion.

**Framework used:** JUnit 5 + `spring-boot-starter-test`
(`@SpringBootTest`, `RANDOM_PORT`) with `java.net.http.HttpClient` — the
same framework/approach already used by the developer's own
`HelloApiToolsTest` and by `hello-world-api`'s existing QA suites. No new
test framework was introduced. `HelloApiToolsTest` itself (the developer's
pre-existing suite) was re-run unmodified and still passes — confirmed via
`git status`/`git diff`, this QA pass added new files only, touching zero
existing test or application code.

## Requirement → test → result

| Req | Description | Test(s) | Result |
|---|---|---|---|
| FR-1 | `POST /mcp` stateless JSON-RPC, `tools/list`/`tools/call` | `fr1_toolsList_exposesExactlyTheThreeExpectedTools_andNoTokenArgOnGetHelloGreeting` | PASS |
| FR-2 | `check_api_health` — no args, real upstream call, no auth required | `fr2nfr7_checkApiHealth_worksWithNoAuthorizationHeader` | PASS |
| FR-3 | `register_user` — username/password args, real upstream call, no auth required | `fr3nfr7_registerUser_worksWithNoAuthorizationHeader_realUpstreamCall` | PASS |
| FR-4 | `login` tool removed | `fr1_toolsList_...` (asserts absent) | PASS |
| FR-5 | `get_hello_greeting` — no token argument, reads SecurityContextHolder, real call-through | `fr1_toolsList_...` (schema has no properties) + `fr5_getHelloGreeting_validCorrectlyAudiencedToken_returnsRealGreetingFromLiveHelloApi` (real greeting returned) + `HelloApiToolsTest` (developer's mocked-upstream unit coverage, unmodified) | PASS |
| FR-6 | `refresh_access_token` tool removed | `fr1_toolsList_...` (asserts absent) | PASS |
| FR-7 | 401 + `WWW-Authenticate` on missing/malformed/wrong-aud token; unprotected tools unaffected | `fr7nfr3_getHelloGreeting_noAuthorizationHeader_...`, `fr7_getHelloGreeting_garbageToken_...`, `nfr2_...unrelatedKey...`, `QaMcpAudienceMismatchRejectsRealTokenTest` | PASS |
| FR-8 | `GET /.well-known/oauth-protected-resource` — unauthenticated 200, RFC 9728 shape | `fr8_protectedResourceMetadata_unauthenticated200WithRequiredFields` | PASS |
| FR-9 | Independent Maven module, own Dockerfile, path-filtered CI workflow | Inspection: `mcp-server/pom.xml` (own `<artifactId>`, not a `<module>` of the root build), `mcp-server/Dockerfile` exists, `.github/workflows/mcp-ci-cd.yml` has `paths: ["mcp-server/**", ...]` | PASS (by inspection — this is a build/deploy-topology requirement, not an HTTP-testable one) |
| NFR-1 | `JwtDecoder` via `spring-boot-starter-oauth2-resource-server`, no hand-rolled JWT verification | Inspection: `mcp-server/pom.xml` has the dependency; `grep` for `MessageDigest`/`Mac.`/`Cipher.`/`SecretKeyFactory` under `mcp-server/src/main/java/com/apitest/mcp/security/` found nothing | PASS (by inspection) |
| NFR-2 | Token signed by an unrelated/unknown key is rejected | `nfr2_getHelloGreeting_validlyStructuredTokenSignedByUnrelatedKey_returns401` (self-signs a syntactically valid RS256 JWT with a freshly generated, unrelated RSA key via Nimbus) | PASS |
| NFR-3 | Every 401 carries `WWW-Authenticate` pointing at `/.well-known/oauth-protected-resource` | `fr7nfr3_...`, `fr7_...garbageToken...`, `nfr2_...`, `QaMcpAudienceMismatchRejectsRealTokenTest` (all assert header presence/content) | PASS |
| NFR-4 | Custom `OAuth2TokenValidator<Jwt>` audience check — not automatic; differently-audienced valid token rejected | `AudienceValidatorTest` (5 isolated unit tests of the exact validator bean: correct aud accepted, wrong aud rejected, multi-value aud with correct entry accepted, missing `aud` claim rejected, empty `aud` list rejected) + `QaMcpAudienceMismatchRejectsRealTokenTest` (real, cryptographically valid, correctly-signed token from a live hello-world-api, `aud=["mcp-server"]`, rejected by an mcp-server instance configured to require a *different* audience) + `fr5_...` (real correct-audience token accepted) | PASS |
| NFR-5 | No raw password/token as a tool argument for *existing-session* auth (`login`/old `get_hello_greeting` token arg gone) | `fr1_toolsList_...` (schema inspection: `get_hello_greeting` has zero parameters; `login`/`refresh_access_token` absent) | PASS |
| NFR-6 | Never logs `Authorization` header, JWT contents, or the `register_user` password | Inspection only: `grep` for any logging statement (`log.`, `logger.`, `LoggerFactory`, `System.out`) under `mcp-server/src/main/java/` found **zero** explicit logging calls anywhere in the module's own code; `logging.level.root: INFO` in `application.yml` with no DEBUG payload logging configured. **No automated test exists or was added** — see Gaps below | NOT TESTED (gap) — PASS by inspection only |
| NFR-7 | `check_api_health`/`register_user` reachable with zero `Authorization` header; all else requires a valid, audience-scoped token | `fr2nfr7_...`, `fr3nfr7_...` (zero-header calls succeed against a real upstream) | PASS |
| NFR-8 | Cloud Run IAM gate set per the confirmed product decision (`--allow-unauthenticated`) | Inspection: `.github/workflows/mcp-ci-cd.yml` line 127 has `--allow-unauthenticated`; `mcp-server/README.md` and `docs/deploy/mcp-server-setup.md` both document and justify this posture, matching Assumption 3 (§5) of the requirements doc | PASS (by inspection — this is a confirmed product decision per the task brief, not re-litigated here) |
| NFR-9 | Dependency/static-security scan run before release | Attempted `mvn dependency:tree`-style scan; no OWASP dependency-check plugin available in this offline sandbox (same limitation already documented for `hello-world-api`'s NFR-10) | NOT TESTED (gap) |

## Real end-to-end coverage (the core ask)

`QaMcpResourceServerIntegrationTest` boots a **real** `mcp-server` Spring
context (`@SpringBootTest`, `RANDOM_PORT`) pointed at a **real, separately
running** `hello-world-api` process — nothing is mocked in this class. It:

1. Confirms `tools/list` exposes exactly `check_api_health`,
   `register_user`, `get_hello_greeting` (and not `login`/
   `refresh_access_token`), and that `get_hello_greeting`'s schema has zero
   parameters.
2. Calls `check_api_health` and `register_user` with **no**
   `Authorization` header at all and confirms both succeed against the
   real upstream API (a real user is actually created in
   `hello-world-api`'s `UserStore`).
3. Calls `get_hello_greeting` with no header, with a garbage token, and
   with a syntactically valid but unrelated-key-signed token — confirms
   `401` + `WWW-Authenticate` in every case.
4. Performs a **real** `authorization_code`+PKCE browser-flow simulation
   against the live `hello-world-api` (register → `/oauth2/authorize` →
   `/login` form with CSRF token → follow the `302` redirect chain →
   `/oauth2/token` exchange with the real client secret) to obtain a
   **real, correctly-audienced** access token, then calls
   `get_hello_greeting` with it and confirms mcp-server calls through to
   the live `hello-world-api` and returns an actual
   `"Hello, <user>!"` / `server_time_utc` greeting — not a stub.
5. Confirms `GET /.well-known/oauth-protected-resource` is unauthenticated
   and well-formed.
6. Mints a real token with a 1-minute TTL, waits a genuine 130 real
   seconds (see Notes), and confirms it is then rejected with `401` — a
   true end-to-end expiry test, not a TTL-claim-only check.

`QaMcpAudienceMismatchRejectsRealTokenTest` and `AudienceValidatorTest`
round out NFR-4 (see table above and Notes).

## Notes / judgment calls

- **Why the expired-token test really waits ~130 real seconds instead of
  faking it.** Spring's default `JwtTimestampValidator` (composed into
  `mcp-server`'s `JwtDecoder` via `JwtValidators.createDefaultWithIssuer`)
  applies a 60-second clock-skew allowance on top of the token's own
  `exp`. With the background `hello-world-api` instance's access-token TTL
  set to the minimum usable value (1 minute, `OAUTH_ACCESS_TOKEN_EXPIRE_MINUTES=1`
  — Spring Authorization Server's `TokenSettings` rejects a
  non-positive TTL, so a "pre-expired" trick like `hello-world-api`'s own
  `QaTokenExpiryTest` negative-TTL approach doesn't work here), a token
  needs upwards of 120 real seconds to be unambiguously expired everywhere.
  Constructing a fake-but-validly-signed expired token isn't possible from
  outside the `hello-world-api` process either, since its RSA signing key
  is generated fresh in memory at process start and never exposed. A
  genuine wait was judged more honest than skipping this case or weakening
  it to a TTL-claim check.
- **NFR-4's "same signing key, different audience" scenario is tested via
  two complementary tests, neither of which asks `hello-world-api` to
  issue two differently-audienced tokens from the exact same live process.**
  That specific black-box scenario turns out to be impractical to construct
  without either modifying application code (not this role's place) or an
  in-process reflection hack confined to `hello-world-api`'s own test
  suite: `hello-world-api`'s OAuth signing key is regenerated fresh at
  every process start (never persisted/exposed), and the `aud` value it
  stamps is a single fixed per-process config value, so two *live,
  separately started* `hello-world-api` processes with different
  `resource-audience` values inevitably also have *different signing
  keys* — conflating "wrong key" (NFR-2) with "wrong audience" (NFR-4).
  Instead: (a) `AudienceValidatorTest` unit-tests the exact validator bean
  directly against synthetic-but-structurally-correct `Jwt` objects
  (correct aud / wrong aud / multi-value aud / missing aud / empty aud),
  and (b) `QaMcpAudienceMismatchRejectsRealTokenTest` uses a **real,
  cryptographically valid** token (genuinely signed by the live
  `hello-world-api`, `aud=["mcp-server"]`) against an `mcp-server` instance
  configured to require a *different* required audience — proving the
  real, wired-up validator (not a mock) rejects a token whose audience
  doesn't match what *this instance* requires, with signature/issuer/expiry
  all genuinely valid. Between the two, NFR-4's literal requirement
  ("a validly-signed token issued by the correct authorization server, with
  a well-formed but different aud value, must be rejected") is fully
  exercised.
- **Mixed Spring Boot major versions across the two modules worked without
  issue in this pass.** `mcp-server` (Boot 4.1.0 / Jackson 3,
  `tools.jackson.databind`) successfully validated tokens issued by
  `hello-world-api` (Boot 3.3.4 / Spring Authorization Server 1.3.2) via
  RFC 8414 issuer-based discovery — confirmed empirically end-to-end, not
  assumed from documentation, per the requirements doc's own instruction
  (mcp-server.md, Handoff §6, final paragraph).

## Findings requiring hello-world-api-side fixes (not mcp-server bugs)

Two real findings came out of this QA pass that live on the
`hello-world-api` side of the integration. Both are written up in full in
`docs/qa/hello-world-api-report.md`'s new dated section (2026-09-21) since
that's the module whose code would need to change:

1. **`hello-world-api`'s own `GET /api/v1/hello` does not check the OAuth
   token's `aud` claim** — a validly-signed token audienced for a
   completely unrelated resource server is still accepted. This was
   explicitly flagged by the developer as a known, intentional gap, and
   this QA pass independently confirmed it happens exactly as flagged.
   `mcp-server` itself is unaffected (its own audience check is confirmed
   working — see NFR-4 above) — this is purely a `hello-world-api`-side
   observation.
2. **The `mcp-server` OAuth client is registered as confidential
   (`client_secret` + mandatory PKCE) rather than a fully public,
   secret-less client**, per a developer-documented deviation from the
   OAuth 2.1 public-client-with-PKCE profile NFR-18 assumes. This QA pass
   independently registered a genuinely public client
   (`ClientAuthenticationMethod.NONE`) against the same
   `hello-world-api` instance and confirmed empirically: the
   `authorization_code` grant with PKCE succeeds for a public client, but
   **no `refresh_token` is issued** — confirming the developer's stated
   reason (Spring Authorization Server 1.3.2 does not issue refresh tokens
   to public clients for this grant) is accurate, not merely asserted.

Neither finding is a `mcp-server` defect — `mcp-server` correctly consumes
whatever `hello-world-api` issues it, per its own NFR-1..NFR-4. They are
recorded here because this QA pass produced the evidence, and in the
`hello-world-api` report because that's the actionable module.

## Gaps: requirements with no (or only partial) automated coverage

- **NFR-6 (never logs `Authorization`/JWT/password) has no automated
  test** — verified by source inspection only (no logging statements exist
  in `mcp-server`'s own code at all, so there is nothing to accidentally
  log at the framework's default `INFO` level). A rigorous test would
  require capturing actual log output (e.g. attaching a test log appender)
  across a real request carrying a live Authorization header and a
  `register_user` call with a live password, then asserting neither value
  appears in the captured output. Not added in this pass — flagged as a
  gap per this role's standard rather than silently treated as covered.
- **NFR-9 (dependency/static-security scan)** — same limitation already
  documented in `hello-world-api`'s QA report: no route to fetch/run
  `org.owasp:dependency-check-maven` or an equivalent scanner in this
  offline sandbox. Must be closed by the team's actual CI pipeline.
- **NFR-8 (Cloud Run IAM gate)** was verified by static inspection of the
  CI workflow file and docs only — this QA pass did not deploy to Cloud
  Run and exercise the actual gate live, since that's an infrastructure
  concern outside this repo's local test harness and the decision itself
  is an explicitly confirmed product call per the task brief (not
  re-litigated here).

## Test files (all written independently by QA)

- `/home/user/apitest/mcp-server/src/test/java/com/apitest/mcp/QaMcpResourceServerIntegrationTest.java` — 9 tests, real end-to-end against a live `hello-world-api`.
- `/home/user/apitest/mcp-server/src/test/java/com/apitest/mcp/QaMcpAudienceMismatchRejectsRealTokenTest.java` — 1 test, real cryptographically-valid-token audience-mismatch rejection.
- `/home/user/apitest/mcp-server/src/test/java/com/apitest/mcp/security/AudienceValidatorTest.java` — 5 tests, isolated unit coverage of the NFR-4 validator bean.

**Total: 21 tests** (6 developer + 15 new QA), all passing as of this
report. `mcp-server`'s own pre-existing `HelloApiToolsTest` (6 tests) was
re-run unmodified as part of the full-suite command above and confirmed
still passing — no regression from this QA pass, which added files only.
