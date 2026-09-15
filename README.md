# Authenticated Hello World API

A small, security-conscious reference API: register → login (JWT access +
refresh tokens) → call a protected `Hello World` endpoint that returns the
current server time.

Built by a simulated BA → Developer → QA → Pentester → Reviewer pipeline —
see `docs/` for each phase's output (technical requirements, pentest
report, final review, and `DEV_NOTES.md` explaining an environment-driven
stack substitution).

## Quick start

```bash
pip install -r requirements.txt   # Flask, pydantic, pydantic-settings, gunicorn
cp .env.example .env
# edit .env: set JWT_SECRET_KEY to a real random value, e.g.
python3 -c "import secrets; print(secrets.token_hex(32))"

python -m app.main                # dev server on http://localhost:8000
```

Production: `gunicorn -w 4 -b 0.0.0.0:8000 app.main:app` behind TLS/a reverse
proxy, with `APP_ENV=production` in the environment.

## Try it

```bash
# Register
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"S3cur3Passw0rd!"}'

# Login -> get tokens
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"S3cur3Passw0rd!"}'

# Call the protected endpoint
curl http://localhost:8000/api/v1/hello -H "Authorization: Bearer <access_token>"
# => {"message": "Hello, alice!", "server_time_utc": "2026-09-15T15:32:22...+00:00"}
```

## Run the tests

```bash
python3 -m unittest tests.test_api -v
```

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/health` | none | Liveness check |
| POST | `/api/v1/auth/register` | none | Create a user (rate-limited) |
| POST | `/api/v1/auth/login` | none | Exchange credentials for tokens (rate-limited) |
| POST | `/api/v1/auth/refresh` | none | Exchange refresh token for new access token (rate-limited) |
| GET | `/api/v1/hello` | Bearer access token | Returns greeting + current UTC time |

## Documentation index

- `docs/requirements/hello-world-api.md` — BA's technical requirements from the business ask
- `docs/DEV_NOTES.md` — why this uses Flask + stdlib crypto instead of the originally planned FastAPI/jose/passlib stack
- `docs/qa/hello-world-api-report.md` — QA verification report (22/22 tests, one bug found & fixed)
- `docs/pentest/hello-world-api-report.md` — pentest findings, including one real vulnerability found and fixed
- `docs/review/hello-world-api-review.md` — final reviewer sign-off
- `docs/BEST_PRACTICES_AND_ROADMAP.md` — best practices applied + improvement plan for production

## The agent pipeline

This repo includes `.claude/agents/` — five isolated Claude Code subagents
(`ba`, `developer`, `qa`, `pentester`, `reviewer`) that build and verify
future features the same way this one was built, but with genuine role
isolation (each runs in its own context, sharing only the documents handed
between stages — see `.claude/agents/README.md`). To build the next
feature: open Claude Code in this repo and ask it to run the ba → developer
→ qa → pentester → reviewer chain on your next requirement.
