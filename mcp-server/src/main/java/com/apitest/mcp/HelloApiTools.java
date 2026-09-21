package com.apitest.mcp;

import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * MCP tools wrapping the Hello World API's REST endpoints. Each tool makes a
 * plain HTTP call to the deployed API (api.base-url) and returns its JSON
 * body. A non-2xx response is translated into the same {"error": "..."}
 * shape the API itself returns, plus the HTTP status, rather than
 * surfacing an opaque MCP protocol error - the calling agent can read and
 * react to it (e.g. explain to the user why a login failed).
 */
@Component
public class HelloApiTools {

    private static final ParameterizedTypeReference<Map<String, Object>> JSON_MAP =
            new ParameterizedTypeReference<>() {
            };

    private final RestClient client;

    public HelloApiTools(RestClient helloApiRestClient) {
        this.client = helloApiRestClient;
    }

    @McpTool(name = "check_api_health", description = "Checks whether the Hello World API is reachable and healthy.")
    public Map<String, Object> checkApiHealth() {
        return call(() -> client.get()
                .uri("/health")
                .retrieve()
                .body(JSON_MAP));
    }

    @McpTool(name = "register_user", description = "Registers a new user account on the Hello World API. "
            + "Username must be 3-32 characters (letters, digits, underscore only); password must be 8-128 characters.")
    public Map<String, Object> registerUser(
            @McpToolParam(description = "Desired username", required = true) String username,
            @McpToolParam(description = "Desired password", required = true) String password) {
        return call(() -> client.post()
                .uri("/api/v1/auth/register")
                .body(Map.of("username", username, "password", password))
                .retrieve()
                .body(JSON_MAP));
    }

    // login and refresh_access_token tools removed (FR-4/FR-6): authentication
    // and token refresh now happen via the standard OAuth 2.1
    // authorization_code+PKCE browser flow and refresh_token grant against
    // hello-world-api's /oauth2/authorize and /oauth2/token, entirely outside
    // the LLM's visible tool-call context - see docs/requirements/mcp-server.md.

    @McpTool(name = "get_hello_greeting", description = "Calls the protected /hello endpoint using the caller's "
            + "authenticated OAuth access token, returning a greeting for the authenticated user and the server's "
            + "current time.")
    public Map<String, Object> getHelloGreeting() {
        // FR-5: no LLM-visible token argument - the caller's identity comes
        // from the security context established by McpToolAuthorizationFilter
        // (see com.apitest.mcp.security) before this method runs. Verified
        // empirically that Spring AI's MCP tool method invocation runs on the
        // same servlet request thread as that filter, so SecurityContextHolder
        // (thread-local by default) reflects the token it validated.
        String rawToken = currentAccessToken();
        if (rawToken == null) {
            // Defensive fallback only: McpToolAuthorizationFilter already
            // rejects an unauthenticated call to this tool with a real HTTP
            // 401 + WWW-Authenticate before this method body ever runs.
            Map<String, Object> error = new LinkedHashMap<>();
            error.put("http_status", 401);
            error.put("error", "Could not validate credentials");
            return error;
        }
        return call(() -> client.get()
                .uri("/api/v1/hello")
                .header("Authorization", "Bearer " + rawToken)
                .retrieve()
                .body(JSON_MAP));
    }

    private static String currentAccessToken() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof JwtAuthenticationToken jwtAuthentication) {
            return jwtAuthentication.getToken().getTokenValue();
        }
        return null;
    }

    private Map<String, Object> call(Supplier<Map<String, Object>> request) {
        try {
            Map<String, Object> body = request.get();
            return body != null ? body : Map.of();
        } catch (RestClientResponseException e) {
            Map<String, Object> error = new LinkedHashMap<>();
            error.put("http_status", e.getStatusCode().value());
            Map<String, Object> body = e.getResponseBodyAs(JSON_MAP);
            if (body != null) {
                error.putAll(body);
            } else {
                error.put("error", e.getStatusText());
            }
            return error;
        }
    }
}
