package com.apitest.oauth;

import jakarta.annotation.PostConstruct;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Configuration for the OAuth 2.1 Authorization Server addition (NFR-13..NFR-20).
 * <p>
 * Bound from {@code application.yml} / environment variables, following the
 * same externalized-configuration + fail-fast posture as {@link com.apitest.config.AppProperties}
 * (see {@link #validate()}): {@code OAUTH_SIGNING_KEY_SECRET} is this
 * capability's equivalent of {@code JWT_SECRET_KEY} — required, never
 * hardcoded, and validated at startup rather than allowed to silently run
 * with a missing/weak value.
 */
@Component
@ConfigurationProperties(prefix = "app.oauth")
public class OAuthProperties {

    /**
     * This Authorization Server's issuer identifier (RFC 8414 {@code issuer}).
     * Must exactly match the base URL this app is reachable at, since OAuth
     * clients/resource servers validate the {@code iss} claim / discovery
     * document against it.
     */
    private String issuer = "http://localhost:8000";

    /** The single pre-registered OAuth client (mcp-server) - see hello-world-api.md §4. */
    private String clientId = "mcp-server";

    /**
     * Client secret for that one pre-registered client (confidential client +
     * mandatory PKCE - see the class-level note on {@link #getClientId()}'s
     * registration in {@code AuthorizationServerConfig} for why this client
     * is confidential rather than a fully public/secret-less client).
     * Required, fail-fast, never hardcoded - same posture as
     * {@link #signingKeySecret}.
     */
    private String clientSecret = "";

    /** Comma-separated list of redirect URIs registered for that one client. */
    private String redirectUris = "http://127.0.0.1:8765/callback";

    /**
     * The {@code aud} (audience, RFC 8707) value stamped onto issued access
     * tokens (NFR-19) - must match the value mcp-server's resource-server
     * audience validator checks for.
     */
    private String resourceAudience = "mcp-server";

    /**
     * Fail-fast gate/entropy source for the Authorization Server's RSA
     * signing key (see {@code com.apitest.oauth.JwkConfig}). RSA key
     * material doesn't reduce to a simple HMAC-style shared secret string
     * the way {@code JWT_SECRET_KEY} does, so this value's role is: (a) the
     * same "fail fast if missing/short" startup gate as JWT_SECRET_KEY, and
     * (b) supplemental entropy mixed into the key generator's SecureRandom.
     * The RSA key pair itself is generated fresh at each process start
     * (never hardcoded/committed), consistent with this demo's documented
     * in-memory/non-persistent-across-restarts posture (hello-world-api.md
     * §4 Out of Scope).
     */
    private String signingKeySecret = "";

    /**
     * OAuth access/refresh token lifetimes - deliberately a separate config
     * surface from {@link com.apitest.config.AppProperties}'s
     * access/refresh minute/day settings, even though both currently
     * default to the same 15-minute/7-day values (NFR-3's original intent):
     * these are a different token family (RSA-signed OAuth access tokens
     * vs. the JSON API's own HS256 jjwt tokens), and QA's existing
     * NFR-3/expiry tests deliberately set
     * {@code app.access-token-expire-minutes} to unusual values (including
     * negative, to simulate an already-expired token) that must not also
     * perturb the unrelated OAuth Authorization Server's token settings.
     */
    private int accessTokenExpireMinutes = 15;

    private int refreshTokenExpireDays = 7;

    @PostConstruct
    public void validate() {
        if (signingKeySecret == null || signingKeySecret.isBlank()) {
            throw new IllegalStateException(
                    "OAUTH_SIGNING_KEY_SECRET is required (set it in the environment or .env)");
        }
        if (signingKeySecret.length() < 32) {
            throw new IllegalStateException("OAUTH_SIGNING_KEY_SECRET must be at least 32 characters long");
        }
        if (clientSecret == null || clientSecret.isBlank()) {
            throw new IllegalStateException(
                    "MCP_OAUTH_CLIENT_SECRET is required (set it in the environment or .env)");
        }
        if (clientSecret.length() < 32) {
            throw new IllegalStateException("MCP_OAUTH_CLIENT_SECRET must be at least 32 characters long");
        }
    }

    public List<String> redirectUriList() {
        return Arrays.stream(redirectUris.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getRedirectUris() {
        return redirectUris;
    }

    public void setRedirectUris(String redirectUris) {
        this.redirectUris = redirectUris;
    }

    public String getResourceAudience() {
        return resourceAudience;
    }

    public void setResourceAudience(String resourceAudience) {
        this.resourceAudience = resourceAudience;
    }

    public String getSigningKeySecret() {
        return signingKeySecret;
    }

    public void setSigningKeySecret(String signingKeySecret) {
        this.signingKeySecret = signingKeySecret;
    }

    public int getAccessTokenExpireMinutes() {
        return accessTokenExpireMinutes;
    }

    public void setAccessTokenExpireMinutes(int accessTokenExpireMinutes) {
        this.accessTokenExpireMinutes = accessTokenExpireMinutes;
    }

    public int getRefreshTokenExpireDays() {
        return refreshTokenExpireDays;
    }

    public void setRefreshTokenExpireDays(int refreshTokenExpireDays) {
        this.refreshTokenExpireDays = refreshTokenExpireDays;
    }
}
