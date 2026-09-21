package com.apitest.oauth;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
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

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
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
