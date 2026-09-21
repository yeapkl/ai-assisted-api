package com.apitest.oauth;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Developer sanity test (not QA's suite) for the QA-flagged gap fix
 * (2026-09-21): {@code hello-world-api}'s own {@code GET /api/v1/hello} now
 * validates the OAuth token's {@code aud} claim, mirroring mcp-server's
 * {@code com.apitest.mcp.security.AudienceValidator} - and this test mirrors
 * that class's own {@code AudienceValidatorTest} exactly, for the identical
 * reason: isolating the pure audience-check logic from network/signature
 * verification (out of scope here, already covered elsewhere), with a real
 * production {@link AudienceValidator} instance and synthetic-but-structurally-
 * correct {@link Jwt} objects - not mocks of the validator itself.
 * <p>
 * Complements {@code OAuthAudienceEnforcementSmokeTest}'s real, live-HTTP
 * coverage of the "correctly audienced token is accepted" case (which a
 * single live instance can exercise honestly); a genuinely wrong-audience
 * *live* token cannot be constructed against this same instance without
 * either a second differently-configured OAuth client or forging a token
 * with the same private key from outside the process - see that class's
 * Javadoc and the handoff notes for the full reasoning traced through
 * {@code HelloApiTools.getHelloGreeting()}'s token-forwarding behavior.
 */
class AudienceValidatorTest {

    private final AudienceValidator validator = new AudienceValidator("hello-world-api");

    @Test
    void tokenWithCorrectAudience_isAccepted() {
        Jwt jwt = jwtWithAudience(List.of("hello-world-api"));
        assertFalse(validator.validate(jwt).hasErrors());
    }

    @Test
    void tokenWithOnlyTheMcpServerAudience_isRejected() {
        // The realistic "before this fix" shape for a token that was never
        // meant to reach this endpoint on its own (aud=[mcp-server] only,
        // no hello-world-api entry) must now be rejected.
        Jwt jwt = jwtWithAudience(List.of("mcp-server"));
        assertTrue(validator.validate(jwt).hasErrors());
    }

    @Test
    void tokenAudiencedForACompletelyUnrelatedResourceServer_isRejected() {
        // QA's exact repro shape: aud=[some-completely-different-resource-server].
        Jwt jwt = jwtWithAudience(List.of("some-completely-different-resource-server"));
        assertTrue(validator.validate(jwt).hasErrors());
    }

    @Test
    void tokenWithBothMcpServerAndHelloWorldApiAudiences_isAccepted() {
        // The real shape AuthorizationServerConfig.jwtCustomizer now stamps
        // for the one registered client (mcp-server), since its access
        // token is used both to call mcp-server's own tools AND, via
        // get_hello_greeting's call-through, this endpoint directly.
        Jwt jwt = jwtWithAudience(List.of("mcp-server", "hello-world-api"));
        assertFalse(validator.validate(jwt).hasErrors());
    }

    @Test
    void tokenWithNoAudienceClaimAtAll_isRejected() {
        Jwt jwt = Jwt.withTokenValue("no-aud")
                .header("alg", "RS256")
                .claim("sub", "someone")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .build();
        assertTrue(validator.validate(jwt).hasErrors(), "a token with no aud claim at all must be rejected");
    }

    @Test
    void tokenWithEmptyAudienceList_isRejected() {
        assertTrue(validator.validate(jwtWithAudience(List.of())).hasErrors());
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
