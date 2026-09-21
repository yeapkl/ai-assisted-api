package com.apitest.mcp.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;

/**
 * NFR-3 / FR-7: every 401 from this resource server carries a
 * {@code WWW-Authenticate} header pointing at
 * {@code /.well-known/oauth-protected-resource} (RFC 9728 §5.1), so a
 * compliant MCP client can discover how to obtain a valid token without
 * prior out-of-band knowledge - a real HTTP 401, not a bare MCP-level
 * JSON-RPC error.
 */
public class McpAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final String resourceMetadataUrl;

    public McpAuthenticationEntryPoint(String resourceMetadataUrl) {
        this.resourceMetadataUrl = resourceMetadataUrl;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setHeader("WWW-Authenticate",
                "Bearer resource_metadata=\"" + resourceMetadataUrl + "\", error=\"invalid_token\"");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(
                "{\"error\":\"invalid_token\",\"error_description\":\"A valid, audience-scoped access token is required\"}");
    }
}
