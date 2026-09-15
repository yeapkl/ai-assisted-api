package app;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

/**
 * Credential handling and token issuance — implemented with the JDK
 * standard library only (javax.crypto/java.security), so production carries
 * zero third-party crypto dependencies to audit. Both primitives used are
 * NIST-approved:
 * - Password hashing: PBKDF2-HMAC-SHA256, 260k iterations, random salt.
 * - Token signing: HMAC-SHA256, in a real JWT (header.payload.signature)
 * envelope, so tokens are still standard, interoperable JWTs.
 */
public final class Security {

    private Security() {
    }

    /** Raised for any invalid, malformed, expired, or tampered token. */
    public static final class TokenException extends Exception {
        public TokenException(String message) {
            super(message);
        }
    }

    public record TokenPayload(String sub, String type, long iat, long exp, String jti) {
    }

    private static final int PBKDF2_ITERATIONS = 260_000;
    private static final int SALT_BYTES = 16;
    private static final int KEY_LENGTH_BITS = 256;
    private static final SecureRandom RANDOM = new SecureRandom();

    // ---------------------------------------------------------------- passwords

    public static String hashPassword(String plainPassword) {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        byte[] digest = pbkdf2(plainPassword, salt, PBKDF2_ITERATIONS);
        return "pbkdf2_sha256$" + PBKDF2_ITERATIONS + "$" + toHex(salt) + "$" + toHex(digest);
    }

    public static boolean verifyPassword(String plainPassword, String hashedPassword) {
        try {
            String[] parts = hashedPassword.split("\\$");
            if (parts.length != 4 || !parts[0].equals("pbkdf2_sha256")) {
                return false;
            }
            int iterations = Integer.parseInt(parts[1]);
            byte[] salt = fromHex(parts[2]);
            byte[] expected = fromHex(parts[3]);
            byte[] candidate = pbkdf2(plainPassword, salt, iterations);
            // constant-time comparison — avoids timing side-channels
            return constantTimeEquals(candidate, expected);
        } catch (Exception e) {
            return false;
        }
    }

    private static byte[] pbkdf2(String password, byte[] salt, int iterations) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, KEY_LENGTH_BITS);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("PBKDF2WithHmacSHA256 not available", e);
        }
    }

    // -------------------------------------------------------------------- JWT

    public static String createToken(String subject, String tokenType, Config cfg) {
        Instant now = Instant.now();
        Instant expire = "access".equals(tokenType)
                ? now.plusSeconds(cfg.accessTokenExpireMinutes * 60L)
                : now.plusSeconds(cfg.refreshTokenExpireDays * 24L * 3600L);

        String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String jti = randomHex(8); // unique id, useful for future revocation lists
        String payload = "{\"sub\":\"" + jsonEscape(subject) + "\",\"type\":\"" + tokenType + "\","
                + "\"iat\":" + now.getEpochSecond() + ",\"exp\":" + expire.getEpochSecond()
                + ",\"jti\":\"" + jti + "\"}";

        String headerB64 = b64UrlEncode(header.getBytes(StandardCharsets.UTF_8));
        String payloadB64 = b64UrlEncode(payload.getBytes(StandardCharsets.UTF_8));
        byte[] signature = hmacSha256(cfg.jwtSecretKey, headerB64 + "." + payloadB64);

        return headerB64 + "." + payloadB64 + "." + b64UrlEncode(signature);
    }

    /** Verifies signature and expiry. Throws TokenException on any problem. */
    public static TokenPayload decodeToken(String token, Config cfg) throws TokenException {
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            throw new TokenException("Malformed token");
        }
        String headerB64 = parts[0];
        String payloadB64 = parts[1];
        String signatureB64 = parts[2];

        byte[] expectedSig = hmacSha256(cfg.jwtSecretKey, headerB64 + "." + payloadB64);
        byte[] providedSig;
        try {
            providedSig = b64UrlDecode(signatureB64);
        } catch (IllegalArgumentException e) {
            throw new TokenException("Malformed token signature");
        }

        // constant-time comparison — prevents signature forgery via timing attack
        if (!constantTimeEquals(expectedSig, providedSig)) {
            throw new TokenException("Invalid signature");
        }

        Map<String, String> fields;
        try {
            fields = JsonUtil.parseFlatObject(new String(b64UrlDecode(payloadB64), StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new TokenException("Malformed token payload");
        }

        try {
            String sub = fields.get("sub");
            String type = fields.get("type");
            long iat = Long.parseLong(fields.get("iat"));
            long exp = Long.parseLong(fields.get("exp"));
            String jti = fields.get("jti");
            if (exp < Instant.now().getEpochSecond()) {
                throw new TokenException("Token expired");
            }
            return new TokenPayload(sub, type, iat, exp, jti);
        } catch (NumberFormatException | NullPointerException e) {
            throw new TokenException("Malformed token payload");
        }
    }

    // --------------------------------------------------------------------- utils

    public static String randomHex(int numBytes) {
        byte[] b = new byte[numBytes];
        RANDOM.nextBytes(b);
        return toHex(b);
    }

    private static byte[] hmacSha256(String key, String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 not available", e);
        }
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }

    private static String b64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private static byte[] b64UrlDecode(String data) {
        return Base64.getUrlDecoder().decode(data);
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] fromHex(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
        }
        return out;
    }

    private static String jsonEscape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
