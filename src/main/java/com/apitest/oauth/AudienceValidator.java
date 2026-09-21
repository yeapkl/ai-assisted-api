package com.apitest.oauth;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * QA-flagged gap fix (2026-09-21): validates that an OAuth access token
 * presented to this app's own {@code GET /api/v1/hello} (via
 * {@code JwtAuthFilter}) carries {@link OAuthProperties#getSelfAudience()}
 * ({@code hello-world-api}) in its {@code aud} claim, mirroring
 * {@code mcp-server}'s own {@code com.apitest.mcp.security.AudienceValidator}
 * pattern exactly (same shape, same fail-closed behavior on a missing/empty
 * {@code aud}) - see that class and {@code JwtDecoderConfig} there for the
 * original.
 * <p>
 * Composed into the OAuth {@link org.springframework.security.oauth2.jwt.JwtDecoder}
 * bean in {@link JwkConfig} via {@code DelegatingOAuth2TokenValidator}, so a
 * failure here surfaces as the same {@code JwtException} that
 * {@code JwtAuthFilter.resolveUsernameFromOAuthToken()} already catches and
 * treats as an authentication failure - no change needed to the filter
 * itself, only to what its decoder accepts.
 */
public class AudienceValidator implements OAuth2TokenValidator<Jwt> {

    private static final OAuth2Error INVALID_AUDIENCE =
            new OAuth2Error("invalid_token", "The required audience is missing", null);

    private final String requiredAudience;

    public AudienceValidator(String requiredAudience) {
        this.requiredAudience = requiredAudience;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        if (token.getAudience() != null && token.getAudience().contains(requiredAudience)) {
            return OAuth2TokenValidatorResult.success();
        }
        return OAuth2TokenValidatorResult.failure(INVALID_AUDIENCE);
    }
}
