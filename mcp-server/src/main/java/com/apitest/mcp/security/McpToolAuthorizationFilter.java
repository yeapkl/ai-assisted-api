package com.apitest.mcp.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;

/**
 * Per-tool OAuth 2.1 enforcement for the single {@code POST /mcp} JSON-RPC
 * endpoint (FR-5, FR-7, NFR-7 in docs/requirements/mcp-server.md).
 * <p>
 * Every MCP tool (protected and unprotected alike) is multiplexed behind
 * one HTTP endpoint and JSON-RPC method ({@code tools/call}), so a standard
 * Spring Security {@code authorizeHttpRequests} URL-pattern rule cannot
 * express "require a Bearer token for the {@code get_hello_greeting} tool
 * call but not for {@code check_api_health}/{@code register_user}" - all
 * three are the same URL and HTTP method. This filter peeks at the
 * buffered JSON-RPC body (see {@link CachedBodyHttpServletRequest}) to make
 * that per-tool decision, then delegates the actual token verification to
 * the standard, Spring-Security-provided {@link JwtDecoder} (NFR-1) - the
 * only "custom" part is the routing decision of *when* to require a token,
 * which is inherent to MCP's single-endpoint JSON-RPC transport, not a
 * hand-rolled verification routine.
 */
public class McpToolAuthorizationFilter extends OncePerRequestFilter {

    /** The one tool that requires an authenticated, audience-scoped caller (FR-5/NFR-7). */
    static final String PROTECTED_TOOL_NAME = "get_hello_greeting";

    private final JwtDecoder jwtDecoder;
    private final AuthenticationEntryPoint authenticationEntryPoint;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public McpToolAuthorizationFilter(JwtDecoder jwtDecoder, AuthenticationEntryPoint authenticationEntryPoint) {
        this.jwtDecoder = jwtDecoder;
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (!"/mcp".equals(request.getRequestURI()) || !"POST".equalsIgnoreCase(request.getMethod())) {
            chain.doFilter(request, response);
            return;
        }

        CachedBodyHttpServletRequest cachedRequest = new CachedBodyHttpServletRequest(request);
        if (!callsProtectedTool(cachedRequest.getCachedBody())) {
            // check_api_health, register_user, tools/list, initialize, etc.
            // (NFR-7): no Authorization header required at all.
            chain.doFilter(cachedRequest, response);
            return;
        }

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
            authenticationEntryPoint.commence(request, response,
                    new InsufficientAuthenticationException("Missing bearer token"));
            return;
        }

        String rawToken = authHeader.substring(7).trim();
        try {
            Jwt jwt = jwtDecoder.decode(rawToken);
            SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt));
            chain.doFilter(cachedRequest, response);
        } catch (JwtException e) {
            authenticationEntryPoint.commence(request, response, new InvalidBearerTokenException(e.getMessage(), e));
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    private boolean callsProtectedTool(byte[] body) {
        try {
            JsonNode root = objectMapper.readTree(body);
            if (root == null || root.isMissingNode()) {
                return false;
            }
            JsonNode methodNode = root.get("method");
            if (methodNode == null || !"tools/call".equals(methodNode.asText())) {
                return false;
            }
            JsonNode nameNode = root.path("params").get("name");
            return nameNode != null && PROTECTED_TOOL_NAME.equals(nameNode.asText());
        } catch (RuntimeException e) {
            // Not parseable JSON-RPC (Jackson 3's ObjectMapper throws
            // unchecked exceptions) - let it fall through unauthenticated;
            // Spring AI's own JSON-RPC handling will produce the appropriate
            // parse-error response for a malformed body.
            return false;
        }
    }
}
