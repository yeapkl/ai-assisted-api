package com.apitest.mcp.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Direct, fast, deterministic unit test of the exact {@link AudienceValidator}
 * bean composed into {@code JwtDecoderConfig}'s {@code JwtDecoder} (NFR-4).
 * Complements {@code QaMcpResourceServerIntegrationTest}'s real HTTP
 * end-to-end coverage: this isolates the audience-check logic itself,
 * independent of network/signature verification (which happens earlier in
 * the {@code JwtDecoder} pipeline and is out of scope for this validator).
 */
class AudienceValidatorTest {

    private final AudienceValidator validator = new AudienceValidator("mcp-server");

    @Test
    void tokenWithCorrectAudience_isAccepted() {
        Jwt jwt = jwtWithAudience(List.of("mcp-server"));
        OAuth2TokenValidatorResult result = validator.validate(jwt);
        assertFalse(result.hasErrors());
    }

    @Test
    void tokenWithDifferentAudience_isRejected() {
        Jwt jwt = jwtWithAudience(List.of("some-other-resource-server"));
        OAuth2TokenValidatorResult result = validator.validate(jwt);
        assertTrue(result.hasErrors());
    }

    @Test
    void tokenWithMultipleAudiencesIncludingCorrectOne_isAccepted() {
        Jwt jwt = jwtWithAudience(List.of("some-other-resource-server", "mcp-server"));
        OAuth2TokenValidatorResult result = validator.validate(jwt);
        assertFalse(result.hasErrors());
    }

    @Test
    void tokenWithNoAudienceClaimAtAll_isRejected() {
        Jwt jwt = Jwt.withTokenValue("no-aud")
                .header("alg", "RS256")
                .claim("sub", "someone")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .build();
        OAuth2TokenValidatorResult result = validator.validate(jwt);
        assertTrue(result.hasErrors(), "a token with no aud claim at all must be rejected, not default-accepted");
    }

    @Test
    void tokenWithEmptyAudienceList_isRejected() {
        Jwt jwt = jwtWithAudience(List.of());
        OAuth2TokenValidatorResult result = validator.validate(jwt);
        assertTrue(result.hasErrors());
    }

    private static Jwt jwtWithAudience(List<String> audience) {
        return Jwt.withTokenValue("token-value")
                .header("alg", "RS256")
                .claim("sub", "someone")
                .claim("aud", audience)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .build();
    }
}
