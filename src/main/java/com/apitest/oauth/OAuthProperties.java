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
     * tokens (NFR-19) - must match the value mcp-server's own,
     * independently-configured resource-server audience validator checks
     * for. Deliberately kept a single value with its original default
     * ({@code mcp-server}), matching how it is already documented/used
     * end-to-end (e.g. {@code docs/qa/mcp-server-report.md}'s own exact
     * reproduction commands set {@code MCP_OAUTH_RESOURCE_AUDIENCE=mcp-server}
     * verbatim) - see {@link #getSelfAudience()}'s Javadoc for why
     * hello-world-api's own audience requirement is a genuinely separate
     * config surface rather than folded into this one as a second
     * comma-separated value: doing that would make the realistic flow
     * silently break for any deployment (including QA's own documented
     * repro script) that keeps setting this to a single value, which this
     * fix must not depend on anyone remembering to change.
     */
    private String resourceAudience = "mcp-server";

    /**
     * hello-world-api's <b>own</b> resource identifier - the specific
     * {@code aud} value that authorizes an OAuth access token to call this
     * app's own protected endpoint, {@code GET /api/v1/hello} (see
     * {@code JwtAuthFilter} / {@code JwkConfig}'s OAuth {@code JwtDecoder}
     * audience validator, mirroring mcp-server's {@code AudienceValidator}
     * pattern exactly).
     * <p>
     * <b>QA-flagged gap fix (2026-09-21):</b> {@code jwtCustomizer} (see
     * {@code AuthorizationServerConfig}) stamps <i>both</i> this value
     * <i>and</i> {@link #resourceAudience} onto every issued access token,
     * unconditionally, regardless of what {@link #resourceAudience} is
     * configured as - traced the actual token flow before deciding this
     * (see {@code HelloApiTools.getHelloGreeting()} in mcp-server): that
     * tool forwards the exact token it received straight through to this
     * app's own {@code GET /api/v1/hello}, so with exactly one registered
     * client, every token this AS issues genuinely needs to satisfy both
     * checks. Per RFC 8707, an {@code aud} claim MAY legitimately list
     * multiple resource servers a token is valid for.
     * <p>
     * Deliberately unconditional (not e.g. folded into {@link #resourceAudience}
     * as a second comma-separated value) so this fix can never regress the
     * realistic mcp-server call-through flow due to a deployment/repro
     * script that keeps {@link #resourceAudience} as a single value (see
     * that field's Javadoc) - this value is always added on top, no matter
     * what. The trade-off, accepted deliberately: a deployment that
     * overrides only {@link #resourceAudience} to represent some other,
     * unrelated resource server's audience (QA's own exact repro scenario)
     * still gets a token this app's own endpoint accepts, since this value
     * is unconditionally present too - correct for today's actual
     * single-client architecture (that "other resource server" doesn't
     * exist as a separately-registered client this AS can distinguish by),
     * not a lingering bug. See {@code com.apitest.oauth.AudienceValidatorTest}
     * for direct, isolated unit coverage of the underlying rejection logic
     * against a token that genuinely lacks this value.
     */
    private String selfAudience = "hello-world-api";

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

    public String getSelfAudience() {
        return selfAudience;
    }

    public void setSelfAudience(String selfAudience) {
        this.selfAudience = selfAudience;
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
