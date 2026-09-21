package com.apitest.oauth;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

/**
 * RSA signing key for the OAuth 2.1 Authorization Server's issued JWTs
 * (NFR-19/NFR-20), published at {@code /oauth2/jwks} for resource servers
 * (mcp-server) to fetch and verify against, instead of a shared symmetric
 * secret (unlike the JSON API's own jjwt/HS256 tokens - these are a
 * different, asymmetric-signed token family by design, since a JWK Set
 * *must* be publishable without revealing anything that could forge a
 * token).
 * <p>
 * Standard {@code java.security.KeyPairGenerator} RSA generation - not a
 * hand-rolled crypto primitive (NFR-11/NFR-20's principle extended here).
 * {@link OAuthProperties#getSigningKeySecret()} is this capability's
 * fail-fast equivalent of {@code JWT_SECRET_KEY}: required and validated at
 * startup (see {@link OAuthProperties#validate()}), and additionally mixed
 * in as supplemental {@link SecureRandom} entropy. The key pair itself is
 * freshly generated on every process start (never hardcoded/committed),
 * consistent with this demo's documented in-memory/non-persistent posture.
 */
@Configuration
public class JwkConfig {

    @Bean
    public JWKSource<SecurityContext> jwkSource(OAuthProperties oAuthProperties) {
        KeyPair keyPair = generateRsaKeyPair(oAuthProperties.getSigningKeySecret());
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * QA-flagged gap fix (2026-09-21): this decoder is consumed <b>only</b>
     * by {@code JwtAuthFilter} as the OAuth-token verification path for this
     * app's own {@code GET /api/v1/hello} - it is not used elsewhere by the
     * Authorization Server itself (verified: no other class in this module
     * injects {@code JwtDecoder}). By default
     * {@code OAuth2AuthorizationServerConfiguration.jwtDecoder(...)} only
     * validates signature/timestamp, not audience - exactly the gap QA
     * found. Composing a {@code DelegatingOAuth2TokenValidator} here, mirroring
     * mcp-server's {@code JwtDecoderConfig} pattern exactly, closes it: a
     * validly-signed, unexpired token whose {@code aud} does not contain
     * this app's own resource identifier ({@link OAuthProperties#getSelfAudience()})
     * is now rejected by {@code oauthJwtDecoder.decode(token)} itself
     * (throwing {@code JwtValidationException}, already caught by
     * {@code JwtAuthFilter.resolveUsernameFromOAuthToken()}'s existing
     * {@code catch (JwtException e)}) - no change to the filter itself was
     * needed.
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource, OAuthProperties oAuthProperties) {
        NimbusJwtDecoder jwtDecoder =
                (NimbusJwtDecoder) OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
        OAuth2TokenValidator<Jwt> defaultValidators = JwtValidators.createDefault();
        OAuth2TokenValidator<Jwt> audienceValidator = new AudienceValidator(oAuthProperties.getSelfAudience());
        jwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(List.of(defaultValidators, audienceValidator)));
        return jwtDecoder;
    }

    private static KeyPair generateRsaKeyPair(String signingKeySecret) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            SecureRandom secureRandom = SecureRandom.getInstanceStrong();
            // Supplemental entropy only (see class Javadoc) - does not make
            // key generation reproducible, and is not relied upon to.
            secureRandom.setSeed(signingKeySecret.getBytes(StandardCharsets.UTF_8));
            keyPairGenerator.initialize(2048, secureRandom);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unable to generate the OAuth Authorization Server's RSA signing key", e);
        }
    }
}
