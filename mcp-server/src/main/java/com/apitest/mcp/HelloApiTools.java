package com.apitest.mcp;

import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.core.ParameterizedTypeReference;
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

    @McpTool(name = "login", description = "Logs in with a username and password, returning a JWT access "
            + "token (short-lived) and refresh token (long-lived).")
    public Map<String, Object> login(
            @McpToolParam(description = "Username", required = true) String username,
            @McpToolParam(description = "Password", required = true) String password) {
        return call(() -> client.post()
                .uri("/api/v1/auth/login")
                .body(Map.of("username", username, "password", password))
                .retrieve()
                .body(JSON_MAP));
    }

    @McpTool(name = "refresh_access_token", description = "Exchanges a valid refresh token for a new access token, "
            + "without needing the username/password again.")
    public Map<String, Object> refreshAccessToken(
            @McpToolParam(description = "A refresh token previously returned by the login tool", required = true) String refreshToken) {
        return call(() -> client.post()
                .uri("/api/v1/auth/refresh")
                .body(Map.of("refresh_token", refreshToken))
                .retrieve()
                .body(JSON_MAP));
    }

    @McpTool(name = "get_hello_greeting", description = "Calls the protected /hello endpoint using a valid access "
            + "token, returning a greeting for the authenticated user and the server's current time.")
    public Map<String, Object> getHelloGreeting(
            @McpToolParam(description = "An access token previously returned by the login tool", required = true) String accessToken) {
        return call(() -> client.get()
                .uri("/api/v1/hello")
                .header("Authorization", "Bearer " + accessToken)
                .retrieve()
                .body(JSON_MAP));
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
