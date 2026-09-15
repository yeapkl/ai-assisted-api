"""
QA verification suite (stdlib unittest — no external test framework needed).
Covers FR-1..FR-7 and the security-relevant behaviors from
NFR-1, NFR-4, NFR-5, NFR-6, NFR-7.

Run: python3 -m unittest tests.test_api -v
"""
import os
import unittest
from datetime import datetime, timezone

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-at-least-32-characters-long")
os.environ.setdefault("APP_ENV", "development")

from app.main import app as flask_app
from app.rate_limit import rate_limiter
from app.security import TokenError, create_token, decode_token, hash_password, verify_password
from app.store import user_store


# --------------------------------------------------------------- unit: crypto

class TestPasswordHashing(unittest.TestCase):
    def test_hash_is_not_plaintext(self):
        hashed = hash_password("mypassword")
        self.assertNotEqual(hashed, "mypassword")
        self.assertTrue(hashed.startswith("pbkdf2_sha256$"))

    def test_verify_correct_and_incorrect(self):
        hashed = hash_password("mypassword")
        self.assertTrue(verify_password("mypassword", hashed))
        self.assertFalse(verify_password("wrongpassword", hashed))

    def test_same_password_different_hashes(self):
        # random salt per hash — protects against rainbow tables
        self.assertNotEqual(hash_password("samepass"), hash_password("samepass"))


class TestTokens(unittest.TestCase):
    def test_roundtrip(self):
        token = create_token("alice", "access")
        payload = decode_token(token)
        self.assertEqual(payload["sub"], "alice")
        self.assertEqual(payload["type"], "access")

    def test_tampered_token_rejected(self):
        token = create_token("alice", "access")
        tampered = token[:-2] + "xx"
        with self.assertRaises(TokenError):
            decode_token(tampered)

    def test_malformed_token_rejected(self):
        with self.assertRaises(TokenError):
            decode_token("not-a-real-token")


# ------------------------------------------------------------- integration

class ApiTestCase(unittest.TestCase):
    def setUp(self):
        flask_app.config.update(TESTING=True)
        user_store._users.clear()
        rate_limiter._hits.clear()  # isolate each test from the shared in-process limiter
        self.client = flask_app.test_client()

    def tearDown(self):
        user_store._users.clear()
        rate_limiter._hits.clear()

    def register(self, username="testuser", password="CorrectHorse123!"):
        return self.client.post("/api/v1/auth/register", json={"username": username, "password": password})

    def login(self, username="testuser", password="CorrectHorse123!"):
        return self.client.post("/api/v1/auth/login", json={"username": username, "password": password})


class TestHealth(ApiTestCase):
    def test_health_check(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), {"status": "ok"})


class TestHelloEndpoint(ApiTestCase):
    def test_requires_auth(self):
        resp = self.client.get("/api/v1/hello")
        self.assertEqual(resp.status_code, 401)

    def test_rejects_malformed_bearer_header(self):
        resp = self.client.get("/api/v1/hello", headers={"Authorization": "NotBearer sometoken"})
        self.assertEqual(resp.status_code, 401)

    def test_full_register_login_hello_flow(self):
        r1 = self.register("bob", "GoodPassw0rd!")
        self.assertEqual(r1.status_code, 201)

        r2 = self.login("bob", "GoodPassw0rd!")
        self.assertEqual(r2.status_code, 200)
        tokens = r2.get_json()
        self.assertIn("access_token", tokens)
        self.assertIn("refresh_token", tokens)

        r3 = self.client.get("/api/v1/hello", headers={"Authorization": f"Bearer {tokens['access_token']}"})
        self.assertEqual(r3.status_code, 200)
        body = r3.get_json()
        self.assertEqual(body["message"], "Hello, bob!")
        self.assertIn("server_time_utc", body)

        ts = datetime.fromisoformat(body["server_time_utc"])
        self.assertLess(abs((datetime.now(timezone.utc) - ts).total_seconds()), 10)

    def test_rejects_tampered_token(self):
        self.register()
        login = self.login()
        token = login.get_json()["access_token"]
        resp = self.client.get("/api/v1/hello", headers={"Authorization": f"Bearer {token}xx"})
        self.assertEqual(resp.status_code, 401)

    def test_refresh_token_cannot_access_protected_route(self):
        """A refresh token must not double as an access token."""
        self.register()
        login = self.login()
        refresh_token = login.get_json()["refresh_token"]
        resp = self.client.get("/api/v1/hello", headers={"Authorization": f"Bearer {refresh_token}"})
        self.assertEqual(resp.status_code, 401)


class TestAuthEndpoints(ApiTestCase):
    def test_duplicate_registration_rejected(self):
        self.register("dup", "GoodPassw0rd!")
        resp = self.register("dup", "AnotherPassw0rd!")
        self.assertEqual(resp.status_code, 400)

    def test_short_password_rejected(self):
        resp = self.register("shortpw", "short")
        self.assertEqual(resp.status_code, 422)

    def test_invalid_username_characters_rejected(self):
        resp = self.register("bad name!", "GoodPassw0rd!")
        self.assertEqual(resp.status_code, 422)

    def test_malformed_json_rejected(self):
        resp = self.client.post("/api/v1/auth/login", data="not-json", content_type="application/json")
        self.assertIn(resp.status_code, (400, 422))

    def test_login_wrong_password_returns_401(self):
        self.register("carol", "GoodPassw0rd!")
        resp = self.login("carol", "wrongpassword")
        self.assertEqual(resp.status_code, 401)

    def test_no_user_enumeration_signal(self):
        """NFR-4: wrong-password and unknown-user errors must be identical."""
        self.register("carol", "GoodPassw0rd!")
        wrong_pw = self.login("carol", "wrongpassword")
        unknown_user = self.login("does-not-exist", "whatever")
        self.assertEqual(wrong_pw.status_code, unknown_user.status_code, 401)
        self.assertEqual(wrong_pw.get_json(), unknown_user.get_json())

    def test_refresh_flow_issues_new_access_token(self):
        self.register()
        login = self.login()
        refresh_token = login.get_json()["refresh_token"]
        resp = self.client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("access_token", resp.get_json())

    def test_access_token_cannot_be_used_to_refresh(self):
        self.register()
        login = self.login()
        access_token = login.get_json()["access_token"]
        resp = self.client.post("/api/v1/auth/refresh", json={"refresh_token": access_token})
        self.assertEqual(resp.status_code, 401)


class TestSecurityHeaders(ApiTestCase):
    def test_headers_present(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(resp.headers.get("Cache-Control"), "no-store")


class TestRateLimiting(ApiTestCase):
    def test_login_throttled_after_limit(self):
        """NFR-5: 11th login attempt within a minute should be throttled (limit=10)."""
        self.register("ratelimited", "GoodPassw0rd!")
        for _ in range(10):
            self.login("ratelimited", "wrongpassword")
        resp = self.login("ratelimited", "wrongpassword")
        self.assertEqual(resp.status_code, 429)


if __name__ == "__main__":
    unittest.main()
