package com.apitest.mcp.security;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * NFR-4: validates the token's {@code aud} claim names this resource server
 * specifically (RFC 8707). Spring's out-of-the-box resource-server
 * configuration validates signature, issuer, and expiry, but NOT audience -
 * this is the explicit, custom {@link OAuth2TokenValidator} the requirements
 * doc calls out as the single most common way this class of MCP/OAuth
 * integration is built incompletely. Composed with the library's own
 * default validators via {@code DelegatingOAuth2TokenValidator} - see
 * {@code JwtDecoderConfig}.
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
