package app;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Unit tests for password hashing and JWT issuance/verification. */
class SecurityTest {

    private static final Config TEST_CONFIG = new Config(Map.of(
            "JWT_SECRET_KEY", "test-secret-key-at-least-32-characters-long",
            "APP_ENV", "development"));

    @Test
    void hashIsNotPlaintext() {
        String hashed = Security.hashPassword("mypassword");
        assertNotEquals("mypassword", hashed);
        assertTrue(hashed.startsWith("pbkdf2_sha256$"));
    }

    @Test
    void verifyCorrectAndIncorrect() {
        String hashed = Security.hashPassword("mypassword");
        assertTrue(Security.verifyPassword("mypassword", hashed));
        assertFalse(Security.verifyPassword("wrongpassword", hashed));
    }

    @Test
    void samePasswordDifferentHashes() {
        // random salt per hash — protects against rainbow tables
        assertNotEquals(Security.hashPassword("samepass"), Security.hashPassword("samepass"));
    }

    @Test
    void tokenRoundtrip() throws Exception {
        String token = Security.createToken("alice", "access", TEST_CONFIG);
        Security.TokenPayload payload = Security.decodeToken(token, TEST_CONFIG);
        assertEquals("alice", payload.sub());
        assertEquals("access", payload.type());
    }

    @Test
    void tamperedTokenRejected() {
        String token = Security.createToken("alice", "access", TEST_CONFIG);
        String tampered = token.substring(0, token.length() - 2) + "xx";
        assertThrows(Security.TokenException.class, () -> Security.decodeToken(tampered, TEST_CONFIG));
    }

    @Test
    void malformedTokenRejected() {
        assertThrows(Security.TokenException.class, () -> Security.decodeToken("not-a-real-token", TEST_CONFIG));
    }
}
