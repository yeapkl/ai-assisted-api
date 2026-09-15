"""
Authenticated Hello World API (Flask).

Run:    python -m app.main            (dev server)
Or:     gunicorn -w 4 -b 0.0.0.0:8000 app.main:app   (production-style)
"""
import secrets
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, g, jsonify, request
from pydantic import ValidationError

from app.config import get_settings
from app.rate_limit import rate_limiter
from app.schemas import LoginRequest, RefreshRequest, RegisterRequest
from app.security import TokenError, create_token, decode_token, hash_password, verify_password
from app.store import user_store

settings = get_settings()
app = Flask(__name__)

# Fixed dummy hash used to equalize login timing for unknown usernames
# (see login() below) — the password it "hashes" is never used to log in.
DUMMY_HASH = hash_password(secrets.token_hex(32))


# ----------------------------------------------------------------- helpers

def error(status_code: int, message: str):
    return jsonify({"error": message}), status_code


def rate_limited(max_requests: int, window_seconds: int):
    """NFR-5: per-IP rate limiting on sensitive endpoints."""

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            client_ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
            key = f"{fn.__name__}:{client_ip}"
            if not rate_limiter.is_allowed(key, max_requests, window_seconds):
                return error(429, "Too many requests. Please try again later.")
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def require_auth(fn):
    """Validates the Bearer access token; NFR-4: generic 401 on any failure."""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return error(401, "Could not validate credentials")

        token = auth_header.removeprefix("Bearer ").strip()
        try:
            payload = decode_token(token)
        except TokenError:
            return error(401, "Could not validate credentials")

        if payload.get("type") != "access":
            return error(401, "Could not validate credentials")

        username = payload.get("sub")
        user = user_store.get(username) if username else None
        if user is None:
            return error(401, "Could not validate credentials")

        g.current_user = user
        return fn(*args, **kwargs)

    return wrapper


# --------------------------------------------------------- security headers

@app.after_request
def security_headers(response):
    """NFR-6: baseline security headers on every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    origin = request.headers.get("Origin")
    if origin and origin in settings.cors_origins_list:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST"
    if settings.app_env == "production":
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


# --------------------------------------------------------------- endpoints

@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/api/v1/auth/register")
@rate_limited(max_requests=5, window_seconds=60)
def register():
    try:
        body = RegisterRequest.model_validate(request.get_json(force=True, silent=True) or {})
    except ValidationError as e:
        return error(422, e.errors()[0]["msg"] if e.errors() else "Invalid input")

    if user_store.exists(body.username):
        # NFR-4: generic message, doesn't confirm the username is taken.
        return error(400, "Registration failed")

    user_store.create(body.username, hash_password(body.password))
    return jsonify({"message": "User registered successfully"}), 201


@app.post("/api/v1/auth/login")
@rate_limited(max_requests=10, window_seconds=60)
def login():
    try:
        body = LoginRequest.model_validate(request.get_json(force=True, silent=True) or {})
    except ValidationError as e:
        return error(422, e.errors()[0]["msg"] if e.errors() else "Invalid input")

    user = user_store.get(body.username)
    # Pentest finding: always run the password hash comparison, even for a
    # nonexistent user, against a fixed dummy hash. Skipping it when the
    # user is unknown created a ~60ms timing side-channel that let an
    # attacker enumerate valid usernames despite the identical error message.
    hashed_to_check = user.hashed_password if user else DUMMY_HASH
    password_ok = verify_password(body.password, hashed_to_check)

    if user is None or not password_ok:
        # NFR-4: identical error whether the username or the password was wrong.
        return error(401, "Invalid credentials")

    return jsonify(
        {
            "access_token": create_token(user.username, "access"),
            "refresh_token": create_token(user.username, "refresh"),
            "token_type": "bearer",
        }
    )


@app.post("/api/v1/auth/refresh")
@rate_limited(max_requests=20, window_seconds=60)
def refresh():
    try:
        body = RefreshRequest.model_validate(request.get_json(force=True, silent=True) or {})
    except ValidationError as e:
        return error(422, e.errors()[0]["msg"] if e.errors() else "Invalid input")

    try:
        payload = decode_token(body.refresh_token)
    except TokenError:
        return error(401, "Invalid refresh token")

    if payload.get("type") != "refresh":
        return error(401, "Invalid refresh token")

    username = payload.get("sub")
    if not username or not user_store.exists(username):
        return error(401, "Invalid refresh token")

    return jsonify({"access_token": create_token(username, "access"), "token_type": "bearer"})


@app.get("/api/v1/hello")
@require_auth
def hello_world():
    return jsonify(
        {
            "message": f"Hello, {g.current_user.username}!",
            "server_time_utc": datetime.now(timezone.utc).isoformat(),
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=(settings.app_env == "development"))
