package com.apitest.mcp.security;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.util.List;

/**
 * NFR-1/NFR-2: OAuth 2.1 resource-server token validation via Spring
 * Security's {@code JwtDecoder} abstraction (issuer-uri based discovery
 * against hello-world-api's {@code /.well-known/oauth-authorization-server}),
 * not hand-rolled JWT parsing/verification - extended with the mandatory
 * custom audience validator (NFR-4, {@link AudienceValidator}).
 */
@Configuration
@EnableConfigurationProperties(OAuthResourceServerProperties.class)
public class JwtDecoderConfig {

    @Bean
    public JwtDecoder jwtDecoder(OAuthResourceServerProperties properties) {
        // JwtDecoders.fromIssuerLocation performs RFC 8414 discovery against
        // <issuer>/.well-known/oauth-authorization-server (falling back to
        // OIDC discovery), wiring up the JWK Set URI it advertises - not a
        // hardcoded JWK Set URI - and returns a NimbusJwtDecoder, verified
        // empirically against hello-world-api's actual metadata endpoint
        // (see handoff notes), not assumed from documentation.
        NimbusJwtDecoder jwtDecoder = (NimbusJwtDecoder) JwtDecoders.fromIssuerLocation(properties.getIssuerUri());

        OAuth2TokenValidator<Jwt> defaultValidators = JwtValidators.createDefaultWithIssuer(properties.getIssuerUri());
        OAuth2TokenValidator<Jwt> audienceValidator = new AudienceValidator(properties.getResourceAudience());
        jwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(List.of(defaultValidators, audienceValidator)));

        return jwtDecoder;
    }
}
