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
