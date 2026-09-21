package com.apitest.mcp;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * Unit tests for the MCP tool wrappers, stubbing the upstream Hello World
 * API with MockRestServiceServer (no real network call, no dependency on a
 * live deployment) - verifies each tool builds the right request and maps
 * both success and error responses correctly.
 */
class HelloApiToolsTest {

    private MockRestServiceServer mockServer;
    private HelloApiTools tools;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder().baseUrl("http://upstream.test");
        mockServer = MockRestServiceServer.bindTo(builder).build();
        tools = new HelloApiTools(builder.build());
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void checkApiHealth_returnsUpstreamBody() {
        mockServer.expect(requestTo("http://upstream.test/health"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("{\"status\":\"ok\"}", MediaType.APPLICATION_JSON));

        Map<String, Object> result = tools.checkApiHealth();

        assertEquals("ok", result.get("status"));
    }

    @Test
    void registerUser_sendsCorrectBodyAndReturnsSuccessMessage() {
        mockServer.expect(requestTo("http://upstream.test/api/v1/auth/register"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(content().json("{\"username\":\"alice\",\"password\":\"S3cur3Passw0rd!\"}"))
                .andRespond(withStatus(HttpStatus.CREATED)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body("{\"message\":\"User registered successfully\"}"));

        Map<String, Object> result = tools.registerUser("alice", "S3cur3Passw0rd!");

        assertEquals("User registered successfully", result.get("message"));
    }

    @Test
    void registerUser_duplicateUsername_returnsErrorBodyWithStatus() {
        mockServer.expect(requestTo("http://upstream.test/api/v1/auth/register"))
                .andRespond(withStatus(HttpStatus.BAD_REQUEST)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body("{\"error\":\"Registration failed\"}"));

        Map<String, Object> result = tools.registerUser("dup", "GoodPassw0rd!");

        assertEquals(400, result.get("http_status"));
        assertEquals("Registration failed", result.get("error"));
    }

    // login and refresh_access_token tools are removed (FR-4/FR-6) - OAuth 2.1
    // authorization_code+PKCE and refresh_token grants against
    // hello-world-api's /oauth2/authorize and /oauth2/token now handle this,
    // outside any MCP tool call.

    @Test
    void getHelloGreeting_usesAuthenticatedJwtAsBearerHeaderAndReturnsGreeting() {
        setAuthenticatedJwt("abc");
        mockServer.expect(requestTo("http://upstream.test/api/v1/hello"))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("Authorization", "Bearer abc"))
                .andRespond(withSuccess(
                        "{\"message\":\"Hello, alice!\",\"server_time_utc\":\"2026-09-20T00:00:00Z\"}",
                        MediaType.APPLICATION_JSON));

        Map<String, Object> result = tools.getHelloGreeting();

        assertEquals("Hello, alice!", result.get("message"));
    }

    @Test
    void getHelloGreeting_upstreamRejectsToken_returns401() {
        setAuthenticatedJwt("tampered");
        mockServer.expect(requestTo("http://upstream.test/api/v1/hello"))
                .andRespond(withStatus(HttpStatus.UNAUTHORIZED)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body("{\"error\":\"Could not validate credentials\"}"));

        Map<String, Object> result = tools.getHelloGreeting();

        assertEquals(401, result.get("http_status"));
        assertEquals("Could not validate credentials", result.get("error"));
    }

    @Test
    void getHelloGreeting_noAuthenticatedPrincipal_returns401WithoutCallingUpstream() {
        // FR-5/NFR-5: no LLM-visible token argument exists on this tool at
        // all; if somehow invoked with no authenticated SecurityContext (the
        // resource-server filter chain normally prevents this - see
        // com.apitest.mcp.security.McpToolAuthorizationFilter), it must fail
        // closed rather than calling the upstream API with no credentials.
        Map<String, Object> result = tools.getHelloGreeting();

        assertEquals(401, result.get("http_status"));
        mockServer.verify();
    }

    private static void setAuthenticatedJwt(String tokenValue) {
        Jwt jwt = Jwt.withTokenValue(tokenValue)
                .header("alg", "RS256")
                .claim("sub", "alice")
                .claim("aud", "mcp-server")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .build();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt));
    }
}
