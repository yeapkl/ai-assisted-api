# Developer Notes: environment constraint (original Python build)

> The API was later ported from Python to Java — see
> `docs/JAVA_PORT_NOTES.md` for the equivalent stack-substitution table.
> This file documents the original Python build's constraints for
> historical context.

This build environment's network egress policy blocks PyPI (`pip install` fails
with `403 host_not_allowed`). So instead of FastAPI + `python-jose` +
`passlib[bcrypt]` + `slowapi` (the originally planned stack), this API is
built entirely from packages already present plus the Python standard
library:

| Originally planned | Used instead | Why it's equivalent |
|---|---|---|
| FastAPI | Flask (already installed) | Same role: WSGI web framework, routing, request/response. |
| `python-jose` (JWT) | Hand-rolled HS256 JWT in `app/security.py` (stdlib `hmac`/`hashlib`/`base64`/`json`) | Produces standard, spec-shaped JWTs (header.payload.signature, HMAC-SHA256), verified with constant-time comparison. Ignoring the token's own `alg` header (always verifying as HS256) also closes the classic `alg=none` forgery class by construction. |
| `passlib[bcrypt]` | PBKDF2-HMAC-SHA256, stdlib `hashlib.pbkdf2_hmac`, 260k iterations, random salt | Both are NIST/OWASP-approved KDFs; PBKDF2 is the FIPS-140-friendly choice when bcrypt isn't available. |
| `slowapi` (rate limiting) | `app/rate_limit.py`, in-process sliding window | Same behavior for a single-process demo; noted in the improvement plan that production needs a shared (Redis-backed) limiter across processes/replicas. |

**Before deploying anywhere real:** run in an environment with normal PyPI
access and (a) install `pip-audit` / `bandit` and run them in CI, (b)
consider swapping back to well-audited libraries (`PyJWT`, `passlib`,
`Flask-Limiter`) if your organization's policy prefers widely-used
dependencies over in-house crypto glue — the implementations here were
reviewed and pentested, but every hand-rolled security primitive carries
more audit burden over time than a maintained library.
