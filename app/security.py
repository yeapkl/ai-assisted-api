"""
Credential handling and token issuance — implemented with the Python
standard library only (hmac/hashlib), because this environment's network
policy blocks PyPI (see docs/DEV_NOTES.md). Both primitives used are
NIST-approved:
  - Password hashing: PBKDF2-HMAC-SHA256, 260k iterations, random salt.
  - Token signing: HMAC-SHA256, in a real JWT (header.payload.signature)
    envelope, so tokens are still standard, interoperable JWTs.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Literal

from app.config import get_settings

settings = get_settings()

PBKDF2_ITERATIONS = 260_000
SALT_BYTES = 16


class TokenError(Exception):
    """Raised for any invalid, malformed, expired, or tampered token."""


# ---------------------------------------------------------------- passwords

def hash_password(plain_password: str) -> str:
    salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", plain_password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        algo, iterations_s, salt_hex, digest_hex = hashed_password.split("$")
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iterations_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (ValueError, AttributeError):
        return False

    candidate = hashlib.pbkdf2_hmac("sha256", plain_password.encode(), salt, iterations)
    # constant-time comparison — avoids timing side-channels
    return hmac.compare_digest(candidate, expected)


# -------------------------------------------------------------------- JWT

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def create_token(subject: str, token_type: Literal["access", "refresh"]) -> str:
    now = datetime.now(timezone.utc)
    if token_type == "access":
        expire = now + timedelta(minutes=settings.access_token_expire_minutes)
    else:
        expire = now + timedelta(days=settings.refresh_token_expire_days)

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": subject,
        "type": token_type,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": secrets.token_hex(8),  # unique id, useful for future revocation lists
    }

    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()

    signature = hmac.new(settings.jwt_secret_key.encode(), signing_input, hashlib.sha256).digest()
    signature_b64 = _b64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{signature_b64}"


def decode_token(token: str) -> dict:
    """Verifies signature and expiry. Raises TokenError on any problem."""
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
    except ValueError:
        raise TokenError("Malformed token")

    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected_sig = hmac.new(settings.jwt_secret_key.encode(), signing_input, hashlib.sha256).digest()

    try:
        provided_sig = _b64url_decode(signature_b64)
    except Exception:
        raise TokenError("Malformed token signature")

    # constant-time comparison — prevents signature forgery via timing attack
    if not hmac.compare_digest(expected_sig, provided_sig):
        raise TokenError("Invalid signature")

    try:
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception:
        raise TokenError("Malformed token payload")

    if payload.get("exp", 0) < time.time():
        raise TokenError("Token expired")

    return payload
