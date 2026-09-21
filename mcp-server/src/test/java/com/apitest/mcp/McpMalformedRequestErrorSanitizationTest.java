package com.apitest.mcp;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression test for the pentest fix in
 * docs/pentest/mcp-oauth-pentest-report.md, Finding 2: {@code POST /mcp}
 * used to leak a full Java stack trace (internal class names,
 * file/line numbers, Spring/Tomcat internals) in the HTTP response body for
 * any malformed or unrecognized JSON-RPC request, fully unauthenticated.
 * Reproduces all three of the pentest report's exact repro shapes
 * (empty {@code {}} body, a batch/array body, a differently-cased/unknown
 * method name) and asserts the response is sanitized.
 * <p>
 * Requires a real, separately running hello-world-api instance (same
 * prerequisite as {@code QaMcpResourceServerIntegrationTest} - see
 * docs/qa/mcp-server-report.md for the exact startup command), because
 * mcp-server's {@code JwtDecoder} bean performs OIDC discovery against it
 * at context startup. None of the three malformed requests below require
 * a token or a successful upstream call - the leak/fix is entirely in
 * mcp-server's own JSON-RPC framing layer.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "oauth.resource-audience=mcp-server",
        "oauth.issuer-uri=${qa.hello-api.base-url:http://localhost:18000}",
        "api.base-url=${qa.hello-api.base-url:http://localhost:18000}"
})
class McpMalformedRequestErrorSanitizationTest {

    private static final String HELLO_API_BASE_URL =
            System.getProperty("qa.hello-api.base-url", "http://localhost:18000");

    @LocalServerPort
    private int mcpPort;

    private static final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    @BeforeAll
    static void verifyHelloApiIsUp() throws Exception {
        HttpResponse<String> health = client.send(
                HttpRequest.newBuilder(URI.create(HELLO_API_BASE_URL + "/health")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, health.statusCode(),
                "This test requires a real hello-world-api running at " + HELLO_API_BASE_URL
                        + " - see docs/qa/mcp-server-report.md for the exact startup command");
    }

    private String mcpUrl() {
        return "http://localhost:" + mcpPort + "/mcp";
    }

    private HttpResponse<String> postToMcp(String rawJsonBody) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(mcpUrl()))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .POST(HttpRequest.BodyPublishers.ofString(rawJsonBody))
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static void assertNoLeak(HttpResponse<String> resp) {
        String body = resp.body();
        assertFalse(body.contains("stackTrace"), "response must not contain a stack trace: " + body);
        assertFalse(body.contains("className"), "response must not contain internal class names: " + body);
        assertFalse(body.contains("suppressed"), "response must not contain Throwable#suppressed: " + body);
        assertFalse(body.toLowerCase().contains("tomcat"), "response must not leak servlet container info: " + body);
        assertFalse(body.contains("org.springframework"), "response must not leak Spring internals: " + body);
        assertFalse(body.contains("io.modelcontextprotocol"), "response must not leak MCP SDK internals: " + body);
        // The intended, spec-shaped JSON-RPC error payload must still be present.
        assertTrue(body.contains("jsonRpcError"), "sanitized error body should still convey a JSON-RPC error: " + body);
    }

    @Test
    void emptyObjectBody_pentestRepro1_returns400WithNoStackTrace() throws Exception {
        HttpResponse<String> resp = postToMcp("{}");
        assertEquals(400, resp.statusCode());
        assertNoLeak(resp);
    }

    @Test
    void batchArrayBody_pentestRepro2_returns400WithNoStackTrace() throws Exception {
        HttpResponse<String> resp = postToMcp(
                "[{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{}}]");
        assertEquals(400, resp.statusCode());
        assertNoLeak(resp);
    }

    @Test
    void differentlyCasedMethodName_pentestRepro3_returns500WithNoStackTrace() throws Exception {
        HttpResponse<String> resp = postToMcp(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"Tools/Call\",\"params\":{}}");
        assertEquals(500, resp.statusCode());
        assertNoLeak(resp);
    }
}
