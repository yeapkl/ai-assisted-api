package com.apitest.security;

import com.apitest.config.AppProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * JWT issuance/verification (FR-1, FR-2, FR-6, NFR-2, NFR-3), implemented with
 * the established {@code io.jsonwebtoken:jjwt} library (NFR-11) instead of
 * the old hand-rolled {@code javax.crypto.Mac}-based HS256 signer/parser.
 */
@Component
public class JwtService {

    /** Raised for any invalid, malformed, expired, or tampered token. */
    public static final class TokenException extends Exception {
        public TokenException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public record TokenPayload(String subject, String type, Instant issuedAt, Instant expiresAt, String id) {
    }

    private static final String CLAIM_TYPE = "type";

    private final AppProperties props;
    private final SecretKey signingKey;

    public JwtService(AppProperties props) {
        this.props = props;
        this.signingKey = Keys.hmacShaKeyFor(props.getJwtSecretKey().getBytes(StandardCharsets.UTF_8));
    }

    public String createToken(String subject, String tokenType) {
        Instant now = Instant.now();
        Instant expiry = "access".equals(tokenType)
                ? now.plusSeconds(props.getAccessTokenExpireMinutes() * 60L)
                : now.plusSeconds(props.getRefreshTokenExpireDays() * 24L * 3600L);

        return Jwts.builder()
                .subject(subject)
                .claim(CLAIM_TYPE, tokenType)
                .id(UUID.randomUUID().toString())
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry))
                .signWith(signingKey, Jwts.SIG.HS256)
                .compact();
    }

    /** Verifies signature and expiry. Throws TokenException on any problem (tampered, expired, malformed). */
    public TokenPayload decodeToken(String token) throws TokenException {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            return new TokenPayload(
                    claims.getSubject(),
                    claims.get(CLAIM_TYPE, String.class),
                    claims.getIssuedAt() != null ? claims.getIssuedAt().toInstant() : null,
                    claims.getExpiration() != null ? claims.getExpiration().toInstant() : null,
                    claims.getId());
        } catch (JwtException | IllegalArgumentException e) {
            // Covers ExpiredJwtException, SignatureException, MalformedJwtException, etc.
            throw new TokenException("Invalid token", e);
        }
    }
}
