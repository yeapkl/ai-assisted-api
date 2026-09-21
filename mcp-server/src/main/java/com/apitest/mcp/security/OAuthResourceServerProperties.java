package com.apitest.mcp.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * OAuth 2.1 resource-server configuration (NFR-1..NFR-4 in
 * docs/requirements/mcp-server.md), following the same env-var-driven
 * pattern as {@link com.apitest.mcp.ApiProperties}'s {@code api.base-url}.
 */
@ConfigurationProperties(prefix = "oauth")
public class OAuthResourceServerProperties {

    /**
     * hello-world-api's Authorization Server issuer - local dev default
     * points at a locally running hello-world-api (see README). Production
     * (Cloud Run) value: the deployed hello-world-api service URL, e.g.
     * {@code https://hello-world-api-mz5e3hbozq-uc.a.run.app} - override via
     * {@code OAUTH_ISSUER_URI}.
     */
    private String issuerUri = "http://localhost:8000";

    /**
     * The audience (RFC 8707 {@code aud}) this resource server requires on
     * every access token (NFR-4) - must match hello-world-api's
     * {@code app.oauth.resource-audience}.
     */
    private String resourceAudience = "mcp-server";

    /**
     * This server's own externally-reachable base URL, used as the RFC 9728
     * {@code resource} identifier in {@code /.well-known/oauth-protected-resource}
     * (FR-8) and as the base of the {@code resource_metadata} URL advertised
     * in {@code WWW-Authenticate} (NFR-3). Local dev default matches
     * {@code server.port}; production (Cloud Run) value: the deployed
     * hello-world-mcp-server service URL - override via
     * {@code MCP_SERVER_BASE_URL}.
     */
    private String resourceBaseUrl = "http://localhost:8080";

    public String getIssuerUri() {
        return issuerUri;
    }

    public void setIssuerUri(String issuerUri) {
        this.issuerUri = issuerUri;
    }

    public String getResourceAudience() {
        return resourceAudience;
    }

    public void setResourceAudience(String resourceAudience) {
        this.resourceAudience = resourceAudience;
    }

    public String getResourceBaseUrl() {
        return resourceBaseUrl;
    }

    public void setResourceBaseUrl(String resourceBaseUrl) {
        this.resourceBaseUrl = resourceBaseUrl;
    }

    public String protectedResourceMetadataUrl() {
        return resourceBaseUrl + "/.well-known/oauth-protected-resource";
    }
}
