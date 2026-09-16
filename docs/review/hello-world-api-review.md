# Final Review — Authenticated Hello World API

> **This review supersedes the prior final review for this feature.** It
> covers the current **Spring Boot 3.3.4 / Java 21** rebuild
> (`docs/requirements/hello-world-api.md`, revised 2026-09), reviewed against
> that revision's FR-1..FR-7 (unchanged), NFR-1..NFR-10 (reworded to mandate
> specific libraries), and the new NFR-11 ("no hand-rolled security/
> cross-cutting primitives"). The original review (of the earlier hand-rolled
> Python/Flask implementation) is preserved verbatim below under "Superseded:
> original Python-build review," for history. That review does not reflect
> the current codebase.

## Verdict: **APPROVED WITH FOLLOW-UPS**

The Spring Boot rebuild satisfies every FR and every NFR that is testable
within this environment; the two requirements QA itself flags as
not-fully-automated (NFR-10, NFR-11) were independently spot-checked by this
review and found genuinely satisfied, just not CI-enforced. No High or
Critical pentest finding exists, so nothing here blocks approval outright.
Six Informational/Low pentest findings and two coverage gaps remain open —
none block shipping the demo as scoped, but several should be tracked (and
one, NFR-10's real scan, must be run before any actual production
deployment, not just before merge). See the numbered follow-up list at the
end.

This review was formed independently: I read
`docs/requirements/hello-world-api.md` first, worked out my own view of what
"done" means for FR-1..FR-7 / NFR-1..NFR-11 before opening the QA or pentest
reports, then cross-referenced QA's requirement-to-test table for coverage
gaps, read the pentest report in full, and spot-checked the implementation
and both reports' claims directly (see "Independent verification performed
by this review" below) rather than relying on the reports' conclusions
alone.

## Requirement-by-requirement checklist

| Req | Requirement (summary) | QA coverage | My assessment |
|---|---|---|---|
| FR-1 | Login issues JWT after verifying credentials | `fr1fr5_login_...` | **Met.** Verified via code read (`AuthController.login`, `JwtService`) and test run. |
| FR-2 | Refresh token issued alongside access token | `fr1fr5_login_...`, `fr2fr3_hello_refreshTokenCannotAccessProtectedRoute` | **Met.** |
| FR-3 | `GET /api/v1/hello` protected, correct response shape | `fr3_hello_...` + 10 negative-path tests | **Met.** Confirmed `JwtAuthFilter` enforces bearer token + type=access + known user. |
| FR-4 | Registration creates hashed-password user, no duplicate races | `fr4_register_...`, concurrency test | **Met.** Read `UserStore.create` (atomic `putIfAbsent`) and `AuthController.register` myself — matches QA's fix description exactly. Independently re-fired 8 concurrent registrations for the same username against the live jar: exactly 1 `201`, rest `400`/`429`, no overwrite (see below). |
| FR-5 | Login exchanges credentials for tokens | `fr1fr5_login_...`, wrong-password/method variants | **Met.** |
| FR-6 | Refresh exchanges refresh token for new access token | `fr6_refresh_...` (5 variants) | **Met.** |
| FR-7 | `GET /health` unauthenticated | `fr7_health_...` | **Met.** Confirmed live (`curl` → `200`). |
| NFR-1 | Bcrypt-class hashing via `PasswordEncoder`, salted, never plaintext/logged | `nfr1_register_...` (asserts `$2[aby]$` prefix, distinct hashes) | **Met.** `SecurityConfig.passwordEncoder()` is a plain `BCryptPasswordEncoder` bean; `PasswordService` never touches raw hashing primitives. |
| NFR-2 | JWT secret from env, established JWT lib, fail-fast on missing/short secret | `QaSecretFailFastTest` (6 tests) | **Met.** Read `JwtService` (uses `Jwts.builder()`/`Jwts.parser()` from `jjwt`, no hand-rolled `Mac`) and `AppProperties.validate()` (throws if secret missing/<32 chars). Confirmed live: server refuses to start without `JWT_SECRET_KEY` (this is exactly the stack trace seen during my own `mvn test` run, from the intentional `QaSecretFailFastTest` case). |
| NFR-3 | Access 15 min / refresh 7 days | `nfr3_...` + real end-to-end expiry test | **Met.** |
| NFR-4 | Identical 401, timing-safe dummy-hash comparison | `nfr4_login_unknownUserAndWrongPasswordReturnByteIdenticalResponses`, timing soft-check; pentest's own live timing measurement (80.65ms vs 80.71ms) | **Met.** Code confirms `PasswordService.dummyHash()` always runs a real bcrypt comparison on the unknown-user path — this is the same fix pattern that closed the prior pentest's High finding on the old Python build. |
| NFR-5 | Rate limiting via established library (Bucket4j), not trivially bypassable | `nfr5_rateLimit_...` (5 tests) + bypass regression test + `QaTrustedProxyRateLimitTest` | **Met.** Read `RateLimitFilter` myself — uses `io.github.bucket4j.Bucket`/`Bandwidth`, keys on `remoteAddr` by default, only honors `X-Forwarded-For` behind an explicit opt-in flag (default `false`). **Independently re-attempted the original spoofed-`X-Forwarded-For` bypass live** against the packaged jar (8 register requests, 8 distinct spoofed IPs, default config): got exactly 5×`201` then 3×`429` — confirms the bypass is closed, matching QA/pentest's re-verification. |
| NFR-6 | Security headers via Spring Security, on all responses | `nfr6_...` (5 tests) | **Met.** Confirmed live: `X-Content-Type-Options: nosniff` present even on 404/415 responses I triggered myself. |
| NFR-7 | Jakarta Bean Validation, 422 + field-level error body | 15 tests | **Met**, with the same caveat QA already flagged (error body is a single string embedding the field name, not structured per-field JSON, and reports only the first violation) — pre-existing behavior carried over unchanged per the requirements doc's "no behavior change" mandate, not a new regression, so not scored as a failure. |
| NFR-8 | CORS explicit allow-list, not wildcard | 4 tests | **Met.** `SecurityConfig.corsConfigurationSource()` reads an explicit list from config, `allowCredentials(false)`, no wildcard. |
| NFR-9 | No sensitive data in logs/error responses | 2 tests + pentest's live log inspection | **Met** for the tested surface. See Follow-up #4 re: the `/error` endpoint and Tomcat-level error pages, which are in the spirit of NFR-9 even though no secret actually leaks there. |
| NFR-10 | Dependency/static-security scan before release | **None — QA-flagged gap** (sandbox has no route to NVD/CISA) | **Not verifiable here, and correctly not claimed as verified by either QA or pentest.** This is a process/CI gate, not a code defect — see Follow-up #1 (must run before real deployment, blocking for production release even though not blocking for this merge). |
| NFR-11 | No hand-rolled security/cross-cutting primitives | Static/manual inspection only — **QA-flagged gap** (no automated test) | **Met, and I verified this myself independently** rather than trusting QA's inspection note. See "Independent verification" below for the exact grep and dependency-tree check I ran. Recommend a lightweight CI-enforced check (Follow-up #5) so this doesn't silently regress. |

## Independent verification performed by this review

1. **Ran the full test suite myself** (not just re-reading QA's numbers):
   ```
   cd /home/user/apitest
   cp .env.example .env
   sed -i "s/^JWT_SECRET_KEY=.*/JWT_SECRET_KEY=$(openssl rand -hex 32)/" .env
   mvn -o test
   ```
   Result: `Tests run: 110, Failures: 0, Errors: 0, Skipped: 0` — `BUILD SUCCESS`. Matches QA's round-2 claim exactly. `.env` was deleted afterward (it is gitignored/untracked and shouldn't be left in the working tree); confirmed `git status --short` is clean post-cleanup.

2. **NFR-11 spot-check (hand-rolled primitives):** grepped `src/main/java` for hand-rolled crypto/JSON patterns (`MessageDigest`, `javax.crypto.*` beyond `SecretKey` typing, `SecretKeyFactory`, `PBKDF2`) — the only hits were `JwtService`'s import of `javax.crypto.SecretKey` (required by jjwt's own API, not a hand-rolled signer) and doc-comments referencing the *old* implementation for contrast. Confirmed `pom.xml` pulls in `jjwt-api/impl/jackson` 0.12.6, `bucket4j-core` 8.10.1, `spring-boot-starter-security`, and `spring-boot-starter-validation`. Confirmed the old hand-rolled `ApiServer.java`/`RateLimiter.java` files no longer exist anywhere in the tree (only referenced in `docs/JAVA_PORT_NOTES.md` for history) — so there's no risk of the hand-rolled code still being reachable. This independently confirms NFR-11 beyond just trusting QA's inspection note.

3. **Re-attempted two of QA's four originally-found bugs live**, against a freshly packaged jar (`mvn -o -DskipTests package`, `java -jar target/hello-world-api.jar`), rather than only trusting the reports:
   - **Bug 2 (rate-limit bypass via spoofed `X-Forwarded-For`):** fired 8 `POST /api/v1/auth/register` requests for distinct usernames, each with a unique spoofed `X-Forwarded-For`, against the default config. Got `201,201,201,201,201,429,429,429` — the 5/60s limit held regardless of the spoofed header; bypass confirmed closed.
   - **Bug 3 / Bug 4 (404 / 415 mapping):** `curl` to an unmapped route returned `404`; `curl` with `Content-Type: text/plain` to `/api/v1/auth/login` returned `415`. Both match the fix and QA/pentest's claims.
   - Also independently reproduced pentest Finding 2 (malformed URI `%ZZ` returns a raw Tomcat HTML 400 page, not the app's JSON error contract) and Finding 3 (`GET /error` returns `500 {...}` with no stack trace/secret) live, confirming both are real but non-leaking as pentest described.

4. **Read the actual fix diffs**, not just QA's summary of them: `UserStore.create` (atomic `putIfAbsent`), `AuthController.register`/`login` (single-source-of-truth conflict decision, always-run dummy-hash comparison), `RateLimitFilter.clientIp()` (opt-in-only `X-Forwarded-For` trust, defaulting closed), and `GlobalExceptionHandler` (explicit `NoHandlerFoundException`/`NoResourceFoundException` → 404 and `HttpMediaTypeNotSupportedException` → 415 handlers, ordered before the generic catch-all). All match what QA described; nothing looks like a shortcut, a disabled check, or a TODO masking a real gap.

## Pentest findings — my judgment on each

All six are Informational/Low; none are High/Medium, so per this review's standard none *block* approval on their own. My own call on which deserve tracked follow-up vs. which are fine to leave as documented, permanent trade-offs:

- **Finding 1 (bcrypt 72-byte truncation vs. 128-char validation):** inherent to bcrypt, not a code defect. Recommend documenting the effective limit (Follow-up #6) — low priority, no code change strictly required.
- **Finding 2 (malformed-URI error-shape inconsistency) and Finding 3 (`/error` reachable):** both touch NFR-9's spirit ("no sensitive data in... error responses") even though neither leaks anything today — the risk is that the *inconsistency* itself is a small crack that could widen (e.g. if stack traces are ever accidentally enabled, this uncontrolled surface wouldn't go through `GlobalExceptionHandler`'s safeguards). I agree with treating these as "fix soon" rather than "fine forever" — see Follow-up #4.
- **Finding 4 (no explicit body-size cap):** mitigated today by rate limiting + Jackson's default 20MB string-length guard; reasonable as a tracked defense-in-depth item (Follow-up #7), not urgent.
- **Finding 5 (`/hello` unrated):** explicitly by design per NFR-5's stated scope (`/auth/*` only) — not a gap, no follow-up needed.
- **Finding 6 (NFR-10 scan blocked by sandbox egress):** this is the one item I'd treat as a hard gate before real production release, not merely a "nice to track" item — see Follow-up #1.

## Follow-ups (ranked by severity/priority — none block this merge, but #1 blocks production release)

1. **[Process, blocks production release, not this merge]** Run a real dependency/CVE scan (OWASP Dependency-Check, Snyk, or GitHub Dependabot) against `pom.xml` in an environment with actual NVD/CISA network access — NFR-10 — before deploying this build anywhere beyond the current sandbox/demo context. Neither QA nor pentest could complete this here; that's an environment limitation, not evidence of safety.
2. **[Low]** Normalize container-level (Tomcat) error responses for malformed URIs (pentest Finding 2) to the app's `{"error": "..."}` JSON contract, e.g. via a Tomcat custom error page/valve, so API consumers get one consistent error shape everywhere.
3. **[Low]** Decide whether `GET /error` should be explicitly mapped/blocked (pentest Finding 3) if a "no reachable framework-default endpoints" posture is desired; currently harmless but avoidable.
4. *(combines the above two, tracked together since both stem from requests that bypass `GlobalExceptionHandler`)* — no code change is required to ship the current demo, but do this before treating NFR-9 as fully closed for a non-demo deployment.
5. **[Informational, process]** Add a lightweight CI check (e.g. an ArchUnit rule or banned-import lint) that fails the build if hand-rolled crypto/JSON/rate-limiting classes (`javax.crypto.Mac`, `MessageDigest`, `SecretKeyFactory`, manual JSON parsing) reappear in `src/main`, so NFR-11 is enforced by the pipeline rather than by a human reading the dependency list each time (as both QA and this review currently must do).
6. **[Informational]** Document the bcrypt 72-byte effective password limit (pentest Finding 1) somewhere consumer-facing (API docs or a code comment on `RegisterRequest.password`), since the 128-char validation limit currently implies more effective entropy than bcrypt actually uses.
7. **[Informational]** Consider an explicit request-body size cap (e.g. `server.tomcat.max-swallow-size` or a request-size-limiting filter) as defense-in-depth independent of rate limiting (pentest Finding 4).
8. **[Informational]** Consider strengthening NFR-7's error body to structured per-field JSON (QA's note) if stricter machine-parseable validation errors are ever required by a consumer — not a regression, just a weak reading of "field-level," carried over unchanged from the prior implementation.

None of the above are blocking for this specific merge/demo release; #1 is the only one I'd insist on before a genuine production deployment.

## Code quality notes

- The four round-1 bugs were root-caused and fixed at the actual source (atomic map operation, opt-in trust flag, explicit exception handlers ordered correctly), not patched over or masked — confirmed by reading the diffs directly, not just QA's description of them.
- Clear separation of concerns matching the requirements doc's Handoff table almost 1:1 (`security/` for JWT+password, `filter/` for rate-limiting+auth, `store/` for the demo user store, `web/` for controllers/DTOs/error mapping) — easy to audit each NFR against exactly one file.
- No hardcoded secrets found anywhere in `src/main` or `pom.xml`; `.env` is gitignored and was not present in the working tree before or after my test run.
- No TODOs or disabled checks found that mask a real gap; the two genuine coverage gaps (NFR-10, NFR-11 automated enforcement) are honestly flagged by QA itself rather than hidden, which is exactly the behavior this review process wants to see.

---

# Superseded: original Python-build review

> Everything below this line is the final review as originally written for
> the earlier Python implementation. It is retained verbatim for history and
> no longer reflects the current Spring Boot codebase — the checklist,
> findings, and verdict above are authoritative for the current build.

# Final Review

**Reviewer checklist against `TECH_REQUIREMENTS.md`:**

- [x] FR-1..FR-7 all implemented and covered by automated tests (22/22 passing).
- [x] NFR-1 (bcrypt-class hashing): PBKDF2-HMAC-SHA256, 260k iterations, random salt per password — equivalent security profile to bcrypt, chosen because it's stdlib-only (see `docs/DEV_NOTES.md` for why).
- [x] NFR-2 (no hardcoded secrets): `JWT_SECRET_KEY` required from environment, app fails fast (Pydantic validation) if missing or under 32 chars. `.env` is gitignored; only `.env.example` (placeholder) is committed.
- [x] NFR-3 (short-lived tokens): 15 min access / 7 day refresh, both configurable via env.
- [x] NFR-4 (no user enumeration): identical error body **and**, after the pentest fix, equalized response timing.
- [x] NFR-5 (rate limiting): per-IP sliding window on all three auth endpoints; confirmed via test and live 429 responses.
- [x] NFR-6 (security headers): nosniff, frame-deny, referrer-policy, cache-control, HSTS (prod only) — verified present on live responses.
- [x] NFR-7 (input validation): Pydantic schemas reject malformed/oversized/malicious input with 422 before any business logic runs.
- [x] NFR-8 (CORS allow-list): explicit origin allow-list, not wildcard.
- [x] NFR-9 (no sensitive data in logs): no password/token values are ever passed to `print`/logging calls in this codebase — confirmed by code read-through.
- [~] NFR-10 (dependency/static scan before release): **could not run in this sandbox** — PyPI/package-index access is blocked by this environment's network egress policy, so `pip-audit`/`bandit` could not be installed or executed here. This is a required CI gate before any real deployment — see improvement plan item 1.

**Code quality notes:**
- Clear separation of concerns (`security.py`, `store.py`, `schemas.py`, `rate_limit.py`, `main.py`) — easy to swap the in-memory store for a real DB later without touching auth logic.
- Every security control traces back to a numbered requirement via inline comments — makes future audits faster.
- The pentest's one real finding (timing side-channel) was root-caused and fixed at the source, not patched over, and the fix is now locked in by the existing test flow (recommend adding a dedicated regression test — flagged in improvement plan).

**Verdict: APPROVED for merge**, conditional on the improvement plan's "before production" items being tracked (not blocking for this deliverable, which was scoped as a demo/reference implementation).
