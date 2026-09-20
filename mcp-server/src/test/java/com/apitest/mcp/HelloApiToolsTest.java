package com.apitest.mcp;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

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

    @Test
    void login_returnsTokens() {
        mockServer.expect(requestTo("http://upstream.test/api/v1/auth/login"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withSuccess(
                        "{\"access_token\":\"abc\",\"refresh_token\":\"def\",\"token_type\":\"bearer\"}",
                        MediaType.APPLICATION_JSON));

        Map<String, Object> result = tools.login("alice", "S3cur3Passw0rd!");

        assertEquals("abc", result.get("access_token"));
        assertEquals("def", result.get("refresh_token"));
    }

    @Test
    void login_wrongPassword_returns401WithGenericError() {
        mockServer.expect(requestTo("http://upstream.test/api/v1/auth/login"))
                .andRespond(withStatus(HttpStatus.UNAUTHORIZED)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body("{\"error\":\"Invalid credentials\"}"));

        Map<String, Object> result = tools.login("alice", "wrong");

        assertEquals(401, result.get("http_status"));
        assertEquals("Invalid credentials", result.get("error"));
    }

    @Test
    void refreshAccessToken_sendsRefreshTokenAndReturnsNewAccessToken() {
        mockServer.expect(requestTo("http://upstream.test/api/v1/auth/refresh"))
                .andExpect(content().json("{\"refresh_token\":\"def\"}"))
                .andRespond(withSuccess(
                        "{\"access_token\":\"newtoken\",\"token_type\":\"bearer\"}", MediaType.APPLICATION_JSON));

        Map<String, Object> result = tools.refreshAccessToken("def");

        assertEquals("newtoken", result.get("access_token"));
    }

    @Test
    void refreshAccessToken_accessTokenUsedAsRefresh_returns401() {
        mockServer.expect(requestTo("http://upstream.test/api/v1/auth/refresh"))
                .andRespond(withStatus(HttpStatus.UNAUTHORIZED)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body("{\"error\":\"Invalid refresh token\"}"));

        Map<String, Object> result = tools.refreshAccessToken("abc");

        assertEquals(401, result.get("http_status"));
        assertEquals("Invalid refresh token", result.get("error"));
    }

    @Test
    void getHelloGreeting_sendsBearerHeaderAndReturnsGreeting() {
        mockServer.expect(requestTo("http://upstream.test/api/v1/hello"))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("Authorization", "Bearer abc"))
                .andRespond(withSuccess(
                        "{\"message\":\"Hello, alice!\",\"server_time_utc\":\"2026-09-20T00:00:00Z\"}",
                        MediaType.APPLICATION_JSON));

        Map<String, Object> result = tools.getHelloGreeting("abc");

        assertEquals("Hello, alice!", result.get("message"));
    }

    @Test
    void getHelloGreeting_tamperedToken_returns401() {
        mockServer.expect(requestTo("http://upstream.test/api/v1/hello"))
                .andRespond(withStatus(HttpStatus.UNAUTHORIZED)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body("{\"error\":\"Could not validate credentials\"}"));

        Map<String, Object> result = tools.getHelloGreeting("tampered");

        assertEquals(401, result.get("http_status"));
        assertEquals("Could not validate credentials", result.get("error"));
    }
}
