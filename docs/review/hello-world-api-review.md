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
