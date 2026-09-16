# QA Verification Report — Authenticated Hello World API

> **This report supersedes all prior QA reports for this feature.** It
> covers the current **Spring Boot 3.3.4 / Java 21** rebuild
> (`docs/requirements/hello-world-api.md`, revised 2026-09) and was produced
> independently of the developer's own sanity suite
> (`src/test/java/com/apitest/ApiIntegrationTest.java`). The original content
> of this file (covering the earlier Python implementation, 22/22 PASS, one
> rate-limiter test-isolation bug found and fixed) is preserved verbatim at
> the bottom of this document under "Superseded: original Python-build
> report", for history. That report does not reflect the current codebase.
>
> **This document has been updated after a second, independent
> re-verification pass** (see "Re-verification (round 2)" below) confirming
> the developer's fixes for all 4 bugs found in round 1. The round-1 verdict
> and bug write-ups immediately below are kept **verbatim, as the historical
> record of what was found** — do not read the "FAIL" verdict text below as
> the current state of the build; see the Re-verification section and the
> "Current verdict" line for that.

## Current verdict (after round 2): **PASS**

All 4 bugs found in round 1 (below) were fixed by the developer and
independently confirmed fixed by re-running the full test suite plus live
manual exploit re-attempts against the packaged jar. See "Re-verification
(round 2)" for full detail, exact commands, and the additional edge-case
tests added this round. No regressions were found in the rest of the suite.

---

## Round 1 verdict (historical): **FAIL**

The implementation correctly satisfies the large majority of FR/NFR
requirements — registration, login, refresh, the protected `/hello`
endpoint, bcrypt hashing, JWT issuance/verification via `jjwt`, Jakarta Bean
Validation with 422 mapping, CORS allow-listing, security headers (including
on error responses), rate limiting via Bucket4j, NFR-4 timing-safe/identical
login-failure responses, and NFR-2's fail-fast secret validation all worked
as specified when independently tested. However, **4 concrete defects** were
found and reproduced deterministically by the independent suite below,
including a real rate-limiting bypass (NFR-5) and a data-corrupting
concurrency bug in registration (FR-4). Per this QA role's standard, any
reproducible failing test means the release verdict is FAIL, not "PASS with
notes" — see the bug list below for exact repro steps.

## How to reproduce this run

```bash
cd /home/user/apitest
cp .env.example .env   # then set JWT_SECRET_KEY, e.g.: sed -i "s/^JWT_SECRET_KEY=.*/JWT_SECRET_KEY=$(openssl rand -hex 32)/" .env
mvn test
```

This runs the full suite: the developer's `ApiIntegrationTest` (17 tests, all
pass) plus this QA pass's independent suite — `QaVerificationTest` (75
tests), `QaProductionHeadersTest` (1), `QaTokenExpiryTest` (1), and
`QaSecretFailFastTest` (6) — for **100 tests total, 4 failures**, all four
in `QaVerificationTest`. To run only the QA suite:

```bash
mvn test -Dtest=QaVerificationTest,QaProductionHeadersTest,QaTokenExpiryTest,QaSecretFailFastTest
```

Framework used: **JUnit 5 + `spring-boot-starter-test`** (`@SpringBootTest`,
`RANDOM_PORT`) with `java.net.http.HttpClient` — the framework already in
use in this repository (`ApiIntegrationTest`); no new test framework was
introduced. Verified offline (`mvn -o test`) against the repo's local Maven
cache, so this is reproducible without network access.

> **Round-2 note:** as of the re-verification pass, `mvn test` now runs
> **110 tests, 0 failures** (100 from round 1, unmodified, plus 10 new
> edge-case regression tests added in round 2 — see "Re-verification
> (round 2)"). The command above is unchanged and still the correct way to
> reproduce the current (passing) result.

## Requirement → test → result

Table below is the **round-1** result (kept for history — see the ✅/status
column added for round 2). Current status of every previously-failing row is
now **PASS** — see "Re-verification (round 2)" for the exact tests and live
re-checks that confirm this.

| Req | Description | Test(s) | Round-1 result | Round-2 status |
|---|---|---|---|---|
| FR-1 | Login issues JWT after verifying credentials | `fr1fr5_login_validCredentialsReturnsAccessAndRefreshTokens` | PASS | PASS (re-run) |
| FR-2 | Refresh token issuance | `fr1fr5_login_validCredentialsReturnsAccessAndRefreshTokens`, `fr2fr3_hello_refreshTokenCannotAccessProtectedRoute` | PASS | PASS (re-run) |
| FR-3 | `GET /api/v1/hello` protected, correct shape | `fr3_hello_validAccessTokenReturnsMessageAndServerTime` + 10 negative-path tests (no header, wrong scheme, lowercase scheme, empty token, tampered sig/payload, alg=none, garbage token, refresh-as-access, unknown type claim, deleted user, wrong method) | PASS | PASS (re-run) |
| FR-4 | Registration creates hashed-password user | `fr4_register_createsUserReturns201`, `nfr1_register_passwordStoredAsBcryptHashNotPlaintext` | PASS | PASS (re-run) |
| FR-4 | Duplicate registration rejected | `fr4_register_duplicateUsernameRejectedWith400GenericBody` (sequential) | PASS | PASS (re-run) |
| FR-4 | Duplicate/conflicting registration under concurrency | `fr4_register_concurrentDuplicateRegistrationsOnlyOneShouldSucceed` | **FAIL — Bug 1** | **FIXED — PASS**, plus live re-verification (see below) |
| FR-5 | Login exchanges credentials for tokens | `fr1fr5_login_validCredentialsReturnsAccessAndRefreshTokens`, `nfr4_login_wrongPasswordReturns401`, wrong-method/malformed/missing-field variants | PASS | PASS (re-run) |
| FR-6 | Refresh exchanges refresh token for new access token | `fr6_refresh_validRefreshTokenReturnsNewAccessToken`, `fr6_refresh_accessTokenCannotBeUsedAsRefreshToken`, `fr6_refresh_tamperedTokenReturns401`, `fr6_refresh_tokenForDeletedUserRejected`, missing-field/malformed/wrong-method variants | PASS | PASS (re-run) |
| FR-7 | `GET /health` unauthenticated | `fr7_health_isUnauthenticatedAndOk`, `fr7_health_wrongMethodReturns405NotCrash` | PASS | PASS (re-run), plus new `general_healthEndpointIgnoresContentTypeHeaderOnGetRequest` |
| NFR-1 | Bcrypt-class hashing, salted, never plaintext | `nfr1_register_passwordStoredAsBcryptHashNotPlaintext` (asserts `$2[aby]$` prefix), `nfr1_register_samePasswordProducesDifferentHashesEachTime` | PASS | PASS (re-run) |
| NFR-2 | JWT secret from env, established JWT lib, fail-fast on missing/short secret | `QaSecretFailFastTest` (4 unit-level + 2 full Spring-context startup tests) | PASS | PASS (re-run) |
| NFR-3 | Access 15 min / refresh 7 days | `nfr3_accessTokenExpiryIs15Minutes`, `nfr3_refreshTokenExpiryIs7Days` (decoded claim TTL), `QaTokenExpiryTest.nfr3_expiredAccessTokenRejectedWith401` (real end-to-end expiry) | PASS | PASS (re-run) |
| NFR-4 | Identical 401 for unknown user vs. wrong password; timing-safe | `nfr4_login_unknownUserAndWrongPasswordReturnByteIdenticalResponses` (byte-identical status+body), `nfr4_login_timingSoftCheck_...` (best-effort latency-ratio check, see Notes) | PASS | PASS (re-run) |
| NFR-5 | Rate limiting via established library (Bucket4j), reduces brute-force risk | `nfr5_rateLimit_registerBlockedAfter5PerMinute`, `..._loginBlockedAfter10PerMinute`, `..._refreshBlockedAfter20PerMinute`, `..._bucketsArePerEndpointNotShared`, `..._consumedEvenByRequestsThatFailValidation` | PASS | PASS (re-run) |
| NFR-5 | Rate limiting cannot be trivially bypassed | `nfr5_rateLimit_bypassableViaSpoofedXForwardedFor_shouldNotBe` | **FAIL — Bug 2** | **FIXED — PASS**, plus extensive live re-verification incl. mixed headers and the opt-in trust-proxy path (see below) |
| NFR-6 | Security headers on all responses, including errors | `nfr6_securityHeadersPresentOnSuccessResponse/On401Response/On422Response/On429Response`, `nfr6_hstsAbsentInDevelopmentEnv`, `QaProductionHeadersTest.nfr6_hstsPresentInProductionEnv` | PASS | PASS (re-run) |
| NFR-7 | Jakarta Bean Validation, 422 + field-level body | 15 tests: boundary lengths (username 2/3/32/33, password 7/8/128/129), invalid chars incl. injection-style payloads, malformed JSON, empty body/object, wrong JSON type, extra fields, oversized (2 MB) payload | PASS (see Notes re: "field-level" body shape) | PASS (re-run) |
| NFR-8 | CORS explicit allow-list, not wildcard | `nfr8_cors_allowedOriginReflectedExactly`, `..._disallowedOriginGetsNoAllowOriginHeaderAndIsRejected`, `..._preflightForAllowedOriginSucceeds`, `..._preflightForDisallowedOriginRejected` | PASS | PASS (re-run) |
| NFR-9 | No sensitive data in logs/error responses | `nfr9_registerResponseNeverEchoesRawPassword`, `nfr9_unexpectedErrorBodyContainsNoStackTraceOrExceptionClassName` | PASS | PASS (re-run) |
| NFR-10 | Dependency/static-security scan run before release | *(none — see Gaps)* | **NOT TESTED (gap)** | still a gap (unchanged; see Gaps) |
| NFR-11 | No hand-rolled crypto/JSON/rate-limit/validation primitives | Static inspection only (see Notes) — not an HTTP-level assertion | PASS (by inspection), **no automated test (gap)** | unchanged; still by-inspection only (see Gaps) |
| — | Unmapped route handling | `general_unknownRouteReturns404NotInternalServerError` | **FAIL — Bug 3** | **FIXED — PASS**, plus new edge-case tests (route-prefix, all HTTP verbs) — see below |
| — | Unsupported `Content-Type` handling | `general_unsupportedContentTypeReturnsClientErrorNot500` | **FAIL — Bug 4** | **FIXED — PASS**, plus new edge-case tests (GET-only endpoint, multipart, missing header, charset suffix) — see below |

## Bugs found (steps to reproduce, expected vs. actual)

> **Status: all 4 bugs below are FIXED as of commit `264abfc`** ("Fix 4
> QA-found bugs: registration race, rate-limit bypass, error mapping") and
> independently confirmed fixed in round 2 — see "Re-verification (round 2)"
> for the fix commit's diff summary and the independent confirmation
> evidence. The write-ups themselves are preserved verbatim below as the
> historical record of what was originally found; they no longer describe
> the current behavior of the code.

### Bug 1 — Registration has a TOCTOU race: concurrent duplicate registrations of the same username can all succeed, silently overwriting each other's password hash (violates FR-4)

**Where:** `AuthController.register()` (`src/main/java/com/apitest/web/AuthController.java`) checks `userStore.exists(username)` and then, in a separate step, calls `userStore.create(...)`, which does an unconditional `Map.put` (`UserStore.create`, `src/main/java/com/apitest/store/UserStore.java`). The exists-check and the create are not atomic.

**Steps to reproduce (automated, deterministic across 3 repeated runs in this environment):**
1. Fire 5 concurrent `POST /api/v1/auth/register` requests for the same username (e.g. `racer_concurrent`) with different passwords, from the same client (so all 5 pass the 5/60s register rate limit).
2. Observe the HTTP status of each response.

Reproduced by `QaVerificationTest.fr4_register_concurrentDuplicateRegistrationsOnlyOneShouldSucceed`:
```
mvn test -Dtest=QaVerificationTest#fr4_register_concurrentDuplicateRegistrationsOnlyOneShouldSucceed
```

**Expected:** Exactly one of the 5 concurrent requests returns `201 Created`; the other 4 return `400` ("Registration failed"), per FR-4's "creates *a* user" and the already-tested sequential duplicate-registration behavior.

**Actual:** All 5 concurrent requests returned `201 Created` (reproduced identically on 3 separate runs). Each successive `create()` call overwrites the previous user record in the `ConcurrentHashMap`, so the final winner's password hash silently becomes "the" password for that username — the other 4 registrants believe they successfully created an account with their own password, but cannot log in with it.

**Fix guidance (for the developer, not applied by QA):** Make user creation atomic, e.g. `UserStore.create` should use `ConcurrentHashMap.putIfAbsent` and return whether the insert actually happened (or throw/return null on conflict), and `AuthController.register` should base its 201/400 decision on that atomic result instead of a separate `exists()` check.

### Bug 2 — Per-IP rate limiting is trivially bypassed by spoofing the `X-Forwarded-For` header (violates NFR-5's stated purpose)

**Where:** `RateLimitFilter.clientIp()` (`src/main/java/com/apitest/filter/RateLimitFilter.java`) unconditionally trusts the client-supplied `X-Forwarded-For` header as the rate-limit key, with no configuration indicating a trusted reverse proxy sits in front of this deployment:
```java
private String clientIp(HttpServletRequest request) {
    String forwarded = request.getHeader("X-Forwarded-For");
    if (forwarded != null && !forwarded.isBlank()) {
        return forwarded;
    }
    ...
}
```

**Steps to reproduce:**
1. Register a user.
2. Send 15 `POST /api/v1/auth/login` requests with wrong credentials, each with a distinct `X-Forwarded-For` header value (e.g. `10.1.2.0`..`10.1.2.14`), from a single real client.
3. Observe that none of the 15 requests receive `429`, even though the login limit is 10/60s.

Reproduced by `QaVerificationTest.nfr5_rateLimit_bypassableViaSpoofedXForwardedFor_shouldNotBe`. Also manually confirmed via curl during this QA pass: 15 login attempts each with a unique `X-Forwarded-For` all returned `401` (never `429`), while 12 attempts reusing one `X-Forwarded-For` value hit `429` starting at attempt 11, exactly as the 10/60s limit specifies.

**Expected:** A single real client (same TCP peer, no trusted proxy configured) cannot evade the per-IP rate limit merely by changing a header it fully controls; brute-force attempts from one machine should still be throttled, per NFR-5's explicit purpose ("to reduce brute-force risk").

**Actual:** Rate limiting is completely defeated for any attacker willing to vary `X-Forwarded-For` per request — i.e., in practice, for any attacker at all. This is a full bypass of NFR-5's core protection, not a partial gap.

**Fix guidance:** Do not trust `X-Forwarded-For` unless request.getRemoteAddr() is a known/trusted reverse-proxy address, and even then only trust the *last* untrusted-network hop per standard reverse-proxy conventions, not the entire client-supplied header. For this demo/single-instance deployment (no proxy documented in §4 Out of Scope), the simplest correct fix is to key the bucket on `request.getRemoteAddr()` only and drop the `X-Forwarded-For` special-case entirely, or gate it behind an explicit "trusted proxy" config flag that defaults to off.

### Bug 3 — Requests to an unmapped route return `500 Internal Server Error` instead of `404 Not Found`

**Steps to reproduce:**
```bash
curl -i http://localhost:8000/api/v1/this-route-does-not-exist
```
Reproduced by `QaVerificationTest.general_unknownRouteReturns404NotInternalServerError`.

**Expected:** `404 Not Found` for a route with no handler.

**Actual:** `500 {"error":"Internal server error"}`. `GlobalExceptionHandler`'s catch-all `@ExceptionHandler(Exception.class)` intercepts the framework's "no handler found" condition and maps it to 500, masking what is unambiguously a client-side routing error, not a server fault. This also pollutes any monitoring/alerting that treats 5xx rates as a server-health signal — a mistyped client URL should never look like a server outage.

**Fix guidance:** Add an explicit `@ExceptionHandler(NoHandlerFoundException.class)` (or `NoResourceFoundException` depending on Spring MVC version/config) mapping to 404, placed so it's matched before the generic `Exception` handler; ensure `spring.mvc.throw-exception-if-no-handler-found=true` (and/or `spring.web.resources.add-mappings=false`) is set so the exception is actually thrown instead of silently falling through to a default resource handler.

### Bug 4 — An unsupported `Content-Type` (e.g. `text/plain`) on a JSON endpoint returns `500 Internal Server Error` instead of a 4xx client error

**Steps to reproduce:**
```bash
curl -i -X POST -H "Content-Type: text/plain" -d 'hello' http://localhost:8000/api/v1/auth/login
```
Reproduced by `QaVerificationTest.general_unsupportedContentTypeReturnsClientErrorNot500`.

**Expected:** A 4xx status (`415 Unsupported Media Type`, or `422` for consistency with this API's existing "malformed request → 422" convention per NFR-7/GlobalExceptionHandler) — this is unambiguously a client input error, the same category NFR-7 already handles specially for malformed JSON bodies.

**Actual:** `500 {"error":"Internal server error"}`. `HttpMediaTypeNotSupportedException` isn't caught by any specific `@ExceptionHandler` in `GlobalExceptionHandler`, so it falls through to the generic `Exception` handler and is reported as a server fault.

**Fix guidance:** Add `@ExceptionHandler(HttpMediaTypeNotSupportedException.class)` to `GlobalExceptionHandler`, mapping to `415` or `422` (pick one consistent with NFR-7's existing convention), alongside the existing `HttpMessageNotReadableException` handler.

---

## Re-verification (round 2)

**Date of this pass:** performed against commit `264abfc` ("Fix 4 QA-found
bugs: registration race, rate-limit bypass, error mapping"), the developer's
fix for the 4 round-1 bugs. Changed files in that commit: `UserStore.java`,
`AuthController.java`, `RateLimitFilter.java`, `GlobalExceptionHandler.java`,
`application.yml`, `.env.example` — **no test file was touched by the fix
commit**, confirmed via `git show 264abfc --stat`.

### Exact command used to run the full suite

```bash
cd /home/user/apitest
cp .env.example .env
sed -i "s/^JWT_SECRET_KEY=.*/JWT_SECRET_KEY=$(openssl rand -hex 32)/" .env
mvn -o test
```

**Result:** `Tests run: 110, Failures: 0, Errors: 0, Skipped: 0` — `BUILD
SUCCESS`. Re-ran twice in full to rule out flakiness; both runs identical
(110/110). Per-class breakdown from the second run:

```
QaProductionHeadersTest      : 1  passed
QaVerificationTest           : 82 passed  (75 original + 7 new this round)
QaTrustedProxyRateLimitTest  : 3  passed  (new this round)
QaTokenExpiryTest            : 1  passed
ApiIntegrationTest           : 17 passed  (developer's own suite, unchanged)
QaSecretFailFastTest         : 6  passed
```

The 4 previously-failing tests were also run individually by name to confirm
each passes on its own, not just as part of the full run:

```bash
mvn -o test -Dtest='QaVerificationTest#fr4_register_concurrentDuplicateRegistrationsOnlyOneShouldSucceed+nfr5_rateLimit_bypassableViaSpoofedXForwardedFor_shouldNotBe+general_unknownRouteReturns404NotInternalServerError+general_unsupportedContentTypeReturnsClientErrorNot500'
```
Result: `Tests run: 4, Failures: 0, Errors: 0, Skipped: 0`.

A diff of the test files against the pre-fix commit confirms no existing QA
test was modified or weakened to force a pass — `git diff` for this round
shows only **additions** (74 new lines in `QaVerificationTest.java`, 0
deletions, plus one new file `QaTrustedProxyRateLimitTest.java`).

### Live manual re-verification against the packaged jar

Beyond the automated suite, each fix was independently re-attempted live
against `target/hello-world-api.jar` (built via `mvn -o -DskipTests
package`), run with the **default** configuration (`.env` copied from
`.env.example`, `RATE_LIMIT_TRUST_X_FORWARDED_FOR` left unset/default) unless
otherwise noted:

**FR-4 registration race —** fired 8 concurrent `POST
/api/v1/auth/register` requests for the same new username with 8 different
passwords. Result: 3 requests hit the 5/60s register rate limit (`429`,
expected/unrelated), and of the remaining 5 that reached the handler,
**exactly 1** returned `201` and the other 4 returned `400
{"error":"Registration failed"}`. Confirmed the winning password (and only
the winning password) can log in afterward; all 4 losing passwords correctly
get `401 {"error":"Invalid credentials"}`. No overwrite/corruption observed.

**NFR-5 rate-limit bypass —** re-attempted the exact original exploit plus
several variations, all against the **default** config (bypass must remain
closed with no special configuration):
- 15 login attempts, each with a distinct spoofed `X-Forwarded-For` value
  (`10.9.9.1`..`10.9.9.15`): correctly throttled with `429` starting at
  request 11 — bypass closed.
- Mixed/varied other commonly-spoofed headers in the same run
  (`X-Real-IP`, `Forwarded`, `True-Client-IP`, `X-Client-IP`,
  `CF-Connecting-IP`, each with a fresh value per request): none of these
  reset or bypassed the bucket either — all correctly fell back to the
  single real-client bucket keyed on `remoteAddr`.
- Explicitly tested the **default** value of the new
  `app.rate-limit.trust-x-forwarded-for` flag by leaving the env var unset
  entirely (not just set to `false`) when starting the jar, confirming the
  documented default (`${RATE_LIMIT_TRUST_X_FORWARDED_FOR:false}` in
  `application.yml`) really does resolve to "closed" in practice, not just
  in the property default declaration.
- Also tested the opt-in `trust-x-forwarded-for=true` path (a separate jar
  run with that env var explicitly set): distinct `X-Forwarded-For` values
  correctly get independent buckets in that mode (expected/intended
  behavior for a deployment that has explicitly asserted a trusted reverse
  proxy sits in front of it — not a bypass, since that's a deliberate
  operator opt-in, and a request with **no** `X-Forwarded-For` header at all
  still falls back to `remoteAddr` and gets rate-limited even with the flag
  on). A comma-separated `X-Forwarded-For` value (`"10.40.1.1,
  10.40.1.2"`-style) was confirmed keyed on the **first** entry per standard
  reverse-proxy convention, not the raw full header string, by holding the
  first entry constant and varying only trailing hops — still hit the same
  bucket. This opt-in path is now covered permanently by
  `QaTrustedProxyRateLimitTest` (new this round, 3 tests, dedicated Spring
  context with `app.rate-limit.trust-x-forwarded-for=true`).

**Bug 3 (404) —** `curl` to `/api/v1/this-route-does-not-exist` now returns
`404 {"error":"Not found"}`. Additional edge cases checked live and now
covered by new automated tests (`QaVerificationTest`, this round):
  - An unmapped path that shares a prefix with a real mapped route (e.g.
    `/api/v1/auth/this-is-not-a-real-auth-endpoint`, sibling to the real
    `/api/v1/auth/{register,login,refresh}`) still correctly 404s rather
    than being caught by some overly-broad prefix match.
  - 404 holds regardless of HTTP verb (`GET`/`POST`/`PUT`/`DELETE`/`PATCH`)
    on an unmapped route — never `405`, never `500`.
  - Regression check: an existing route hit with the *wrong* method (e.g.
    `DELETE /health`) still correctly returns `405`, confirming the 404 fix
    did not collapse that pre-existing, distinct behavior into 404.
  - Other manually-checked variants, all correctly 404 (not added as
    separate automated tests, low marginal value over the above): case
    changes (`/API/V1/HELLO`), root path `/`, trailing slash (`/health/`),
    static-resource-looking paths (`/favicon.ico`).

**Bug 4 (415) —** `curl` with `Content-Type: text/plain` to
`/auth/login` now returns `415 {"error":"Unsupported Content-Type"}`.
Additional edge cases checked live and now covered by new automated tests
(`QaVerificationTest`, this round):
  - `GET /health` (a GET-only, bodyless endpoint) with a nonsense
    `Content-Type: text/plain` header still correctly returns `200` — the
    415 handler is scoped to requests Spring actually attempts to
    deserialize a body for, and does not misfire on unrelated GET requests.
  - `multipart/form-data` and a **missing** `Content-Type` header entirely
    (with a body present) both correctly return `415`.
  - Regression check: `application/json;charset=utf-8` (a common, legitimate
    variant) and mixed-case `APPLICATION/JSON` are still accepted (reach
    normal auth handling, `401` for bad credentials) — confirming the fix
    isn't so strict it rejects standard `Content-Type` variants.

### New test files/cases added this round

- `src/test/java/com/apitest/QaVerificationTest.java` — **7 new tests**
  appended (no existing test modified): 404-prefix edge case, 404
  across-all-verbs, 405-vs-404 regression guard, `/health` GET ignoring bad
  `Content-Type`, 415 for multipart, 415 for missing `Content-Type`, and a
  regression guard that `application/json;charset=utf-8` is still accepted.
- `src/test/java/com/apitest/QaTrustedProxyRateLimitTest.java` — **new
  file, 3 tests**, dedicated Spring context with
  `app.rate-limit.trust-x-forwarded-for=true`, covering the opt-in
  trusted-proxy path: independent buckets per distinct `X-Forwarded-For`
  when explicitly trusted, first-entry-of-comma-list keying, and fallback to
  `remoteAddr` when the header is absent even with the flag on.

### Conclusion of round 2

All 4 round-1 bugs are confirmed fixed, both by the automated suite
(110/110, including the 4 originally-failing tests run individually by
name) and by independent, hands-on exploit re-attempts against the packaged
jar covering the specific edge cases requested for this pass (mixed spoofed
headers, the trust-flag default path, route-prefix and cross-method 404s,
and GET-only-endpoint / charset / multipart 415 behavior). No regressions
were found elsewhere in the suite. **Verdict: PASS.**

## Notes / judgment calls (not failures, flagged for completeness)

- **NFR-7 "field-level error body" is a single string, not structured per-field data, and only reports the first violation.** E.g. `{"error":"username: length must be between 3 and 32 characters"}` — the field name is embedded in a message string rather than returned as a separate `field` key, and if both `username` and `password` are invalid simultaneously, only one violation is reported. This matches the pre-existing, previously-reviewed behavior (per §5 of the requirements doc, "constraints and messages are kept identical to the previous implementation") and is not a regression introduced by this rebuild, so it is **not scored as a failure here** — but it is a weak reading of "field-level error body" and worth a product/BA decision if stricter machine-parseable validation errors are ever required.
- **NFR-4 timing-safety check is best-effort only.** `nfr4_login_timingSoftCheck_...` asserts the average latency ratio between unknown-user and wrong-password logins stays under 3x over 15 iterations in a shared, noisy CI-like environment — sufficient to catch a gross regression (e.g. the dummy-hash comparison being skipped again, as the prior pentest found), but it is not a rigorous statistical timing-attack proof. A dedicated, larger-sample timing analysis is out of scope for a functional QA suite and would belong in a pentest-style engagement.
- **Oversized-payload handling has no hard body-size cap.** A 2 MB JSON body was handled gracefully (422, no crash), which is what this pass tested — but no test exercised gigabyte-scale payloads, and the code does not appear to configure a request body size limit (e.g. via `server.tomcat.max-swallow-size` or a servlet-level limit) for JSON bodies read directly by Jackson. This is a potential resource-exhaustion vector on a public-facing deployment; flagged as a gap, not a confirmed bug (not explicitly required by any FR/NFR).
- **(Round 2) The opt-in `app.rate-limit.trust-x-forwarded-for=true` path is inherently spoofable by design if ever misconfigured/misused** — e.g. if an operator enables it without actually deploying behind a reverse proxy that overwrites the header, the original Bug 2 bypass returns. This is expected/inherent to the trusted-proxy trust model (the flag's entire purpose is to say "I attest a proxy controls this header"), not a new defect, and is clearly documented in code comments and `.env.example`. Flagged here only so it isn't mistaken for a residual bypass of the *default* configuration, which remains closed.

## Gaps: requirements with no (or only partial) automated coverage

- **NFR-10 (dependency/static-security scan run before release): no automated test exists, and none could be added here.** This is a CI/process requirement, not something exercisable via HTTP or unit tests. An attempt to run `mvn dependency:tree`/`org.owasp:dependency-check-maven` in this sandbox failed because the plugin isn't in the offline-only local Maven cache and this environment has no route to fetch it or the NVD CVE database. This gap must be closed by the team's actual CI pipeline, not by this QA pass. **(Unchanged in round 2.)**
- **NFR-11 (no hand-rolled security primitives) was verified only by static/manual inspection, not an automated test:** confirmed via `pom.xml` (lists `jjwt-api/impl/jackson`, `bucket4j-core`, `spring-boot-starter-security`, `spring-boot-starter-validation`, `spring-boot-starter-web`) and a source grep for hand-rolled crypto/parsing patterns (`MessageDigest`, `javax.crypto.Mac`, `PBKDF2`, `SecretKeyFactory`, manual JSON parsing) in `src/main/java`, which found none outside of doc comments referencing the *old* implementation. Per this role's standard, a requirement with no corresponding automated test is itself a finding — flagging that NFR-11 currently relies on a QA human reading the dependency list and source tree rather than a repeatable, CI-enforced check (e.g. a build-time rule against specific banned imports/classes). **(Unchanged in round 2; the round-2 fix commit touched none of the dependency list.)**
- **Distributed/multi-instance rate limiting** is explicitly out of scope per §4 of the requirements doc and was not tested (single-process, in-memory Bucket4j only). **(Unchanged in round 2.)**

## Test files (all written independently by QA, not reusing the developer's `ApiIntegrationTest`)

- `/home/user/apitest/src/test/java/com/apitest/QaVerificationTest.java` — 82 tests (75 from round 1 + 7 new in round 2), main FR/NFR + edge-case suite.
- `/home/user/apitest/src/test/java/com/apitest/QaProductionHeadersTest.java` — 1 test, HSTS-in-production check (dedicated Spring context).
- `/home/user/apitest/src/test/java/com/apitest/QaTokenExpiryTest.java` — 1 test, real end-to-end expired-access-token rejection (dedicated Spring context, negative TTL).
- `/home/user/apitest/src/test/java/com/apitest/QaSecretFailFastTest.java` — 6 tests, NFR-2 fail-fast secret validation (unit-level + full Spring Boot startup).
- `/home/user/apitest/src/test/java/com/apitest/QaTrustedProxyRateLimitTest.java` — **new in round 2**, 3 tests, NFR-5 opt-in `trust-x-forwarded-for=true` path (dedicated Spring context).

**Total: 110 tests** (100 from round 1 + 10 new in round 2), all passing as of this report.

---

# Superseded: original Python-build report

> Everything below this line is the QA report as originally written for the
> earlier Python implementation. It is retained verbatim for history and no
> longer reflects the current Spring Boot codebase (routes, status codes,
> and pass/fail results above are authoritative for the current build).

# QA Verification Report — Authenticated Hello World API

> This report covers the original Python implementation. The API was later
> ported to Java (`mvn test`), carrying over the same 22 test cases with
> equivalent coverage — see `docs/JAVA_PORT_NOTES.md`.

**Verdict: PASS** (22/22 tests) — one bug found and fixed during this run.

**Run with:** `python3 -m unittest tests.test_api -v` (original Python build)

## Requirement → test coverage

| Requirement | Test(s) | Result |
|---|---|---|
| FR-1/FR-5 login issues tokens | `test_full_register_login_hello_flow` | PASS |
| FR-2/FR-6 refresh flow | `test_refresh_flow_issues_new_access_token`, `test_access_token_cannot_be_used_to_refresh` | PASS |
| FR-3 protected hello endpoint | `test_requires_auth`, `test_full_register_login_hello_flow` | PASS |
| FR-4 registration | `test_duplicate_registration_rejected`, `test_short_password_rejected`, `test_invalid_username_characters_rejected` | PASS |
| FR-7 health check | `test_health_check` | PASS |
| NFR-1 password hashing | `test_hash_is_not_plaintext`, `test_verify_correct_and_incorrect`, `test_same_password_different_hashes` | PASS |
| NFR-3 token lifetime/typing | `test_roundtrip`, `test_refresh_token_cannot_access_protected_route` | PASS |
| NFR-4 no user enumeration (response body) | `test_no_user_enumeration_signal` | PASS |
| NFR-5 rate limiting | `test_login_throttled_after_limit` | PASS |
| NFR-6 security headers | `test_headers_present` | PASS |
| NFR-7 input validation | `test_short_password_rejected`, `test_invalid_username_characters_rejected`, `test_malformed_json_rejected` | PASS |
| Token forgery resistance | `test_tampered_token_rejected`, `test_malformed_token_rejected`, `test_rejects_tampered_token` | PASS |

## Bug found during this QA pass
The shared in-process rate limiter was not reset between test cases, so
tests ran against each other's request counts and intermittently returned
429 instead of the expected status. **Fixed**: `setUp`/`tearDown` now clear
`rate_limiter._hits` per test. This is a test-isolation fix only — the
rate limiter's production behavior (shared per-IP state within one process)
is unchanged and was itself the thing under test in
`test_login_throttled_after_limit`.

## Gaps / not covered here (flagged, not blocking)
- No load/concurrency testing of the rate limiter across simulated
  multiple processes (single-process limiter is a known limitation, see
  `docs/BEST_PRACTICES_AND_ROADMAP.md`).
- No test asserts the *absence* of sensitive data in logs (would require
  capturing and inspecting log output directly) — recommend adding this
  once real logging is wired up.
