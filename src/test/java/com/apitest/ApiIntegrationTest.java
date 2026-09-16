package com.apitest;

import com.apitest.filter.RateLimitFilter;
import com.apitest.store.UserStore;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Minimal sanity tests confirming the Spring Boot rebuild compiles and the
 * core FR-1..FR-7 / NFR-4 / NFR-5 / NFR-7 flows behave as before, run
 * against a real embedded server via {@code java.net.http.HttpClient} (same
 * approach as the pre-Spring-Boot test suite). This is NOT the deliverable
 * test suite — QA owns the independent suite.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "app.jwt-secret-key=test-secret-key-at-least-32-characters-long",
        "app.app-env=development"
})
class ApiIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private UserStore userStore;

    @Autowired
    private FilterRegistrationBean<RateLimitFilter> rateLimitFilterRegistration;

    private final ObjectMapper mapper = new ObjectMapper();
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    @BeforeEach
    void resetState() {
        userStore.clear();
        rateLimitFilterRegistration.getFilter().clear();
    }

    private String baseUrl(String path) {
        return "http://localhost:" + port + path;
    }

    private HttpResponse<String> post(String path, Map<String, String> body) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl(path)))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
                .build();
        return client.send(req, HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> get(String path, String authorizationHeader) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(baseUrl(path))).GET();
        if (authorizationHeader != null) {
            b.header("Authorization", authorizationHeader);
        }
        return client.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> register(String username, String password) throws Exception {
        return post("/api/v1/auth/register", Map.of("username", username, "password", password));
    }

    private HttpResponse<String> login(String username, String password) throws Exception {
        return post("/api/v1/auth/login", Map.of("username", username, "password", password));
    }

    @Test
    void healthCheck() throws Exception {
        HttpResponse<String> resp = get("/health", null);
        assertEquals(200, resp.statusCode());
        assertTrue(resp.body().contains("\"status\":\"ok\""));
    }

    @Test
    void helloRequiresAuth() throws Exception {
        assertEquals(401, get("/api/v1/hello", null).statusCode());
    }

    @Test
    void helloRejectsMalformedBearerHeader() throws Exception {
        assertEquals(401, get("/api/v1/hello", "NotBearer sometoken").statusCode());
    }

    @Test
    void fullRegisterLoginHelloFlow() throws Exception {
        assertEquals(201, register("bob", "GoodPassw0rd!").statusCode());

        HttpResponse<String> loginResp = login("bob", "GoodPassw0rd!");
        assertEquals(200, loginResp.statusCode());
        JsonNode tokens = mapper.readTree(loginResp.body());
        assertNotNull(tokens.get("access_token").asText());
        assertNotNull(tokens.get("refresh_token").asText());

        HttpResponse<String> helloResp = get("/api/v1/hello", "Bearer " + tokens.get("access_token").asText());
        assertEquals(200, helloResp.statusCode());
        JsonNode body = mapper.readTree(helloResp.body());
        assertEquals("Hello, bob!", body.get("message").asText());
        assertNotNull(body.get("server_time_utc"));

        Instant ts = Instant.parse(body.get("server_time_utc").asText());
        assertTrue(Math.abs(Duration.between(ts, Instant.now()).toSeconds()) < 10);
    }

    @Test
    void rejectsTamperedToken() throws Exception {
        register("testuser", "CorrectHorse123!");
        HttpResponse<String> loginResp = login("testuser", "CorrectHorse123!");
        String token = mapper.readTree(loginResp.body()).get("access_token").asText();
        assertEquals(401, get("/api/v1/hello", "Bearer " + token + "xx").statusCode());
    }

    @Test
    void refreshTokenCannotAccessProtectedRoute() throws Exception {
        register("testuser", "CorrectHorse123!");
        HttpResponse<String> loginResp = login("testuser", "CorrectHorse123!");
        String refreshToken = mapper.readTree(loginResp.body()).get("refresh_token").asText();
        assertEquals(401, get("/api/v1/hello", "Bearer " + refreshToken).statusCode());
    }

    @Test
    void duplicateRegistrationRejected() throws Exception {
        register("dup", "GoodPassw0rd!");
        assertEquals(400, register("dup", "AnotherPassw0rd!").statusCode());
    }

    @Test
    void shortPasswordRejectedWith422() throws Exception {
        assertEquals(422, register("shortpw", "short").statusCode());
    }

    @Test
    void invalidUsernameCharactersRejectedWith422() throws Exception {
        assertEquals(422, register("bad name!", "GoodPassw0rd!").statusCode());
    }

    @Test
    void malformedJsonRejectedWith422() throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl("/api/v1/auth/login")))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("not-json"))
                .build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(422, resp.statusCode());
    }

    @Test
    void loginWrongPasswordReturns401() throws Exception {
        register("carol", "GoodPassw0rd!");
        assertEquals(401, login("carol", "wrongpassword").statusCode());
    }

    @Test
    void noUserEnumerationSignal() throws Exception {
        // NFR-4: wrong-password and unknown-user errors must be byte-identical.
        register("carol", "GoodPassw0rd!");
        HttpResponse<String> wrongPw = login("carol", "wrongpassword");
        HttpResponse<String> unknownUser = login("does-not-exist", "whatever");
        assertEquals(wrongPw.statusCode(), unknownUser.statusCode());
        assertEquals(wrongPw.body(), unknownUser.body());
    }

    @Test
    void refreshFlowIssuesNewAccessToken() throws Exception {
        register("testuser", "CorrectHorse123!");
        HttpResponse<String> loginResp = login("testuser", "CorrectHorse123!");
        String refreshToken = mapper.readTree(loginResp.body()).get("refresh_token").asText();
        HttpResponse<String> resp = post("/api/v1/auth/refresh", Map.of("refresh_token", refreshToken));
        assertEquals(200, resp.statusCode());
        assertNotNull(mapper.readTree(resp.body()).get("access_token"));
    }

    @Test
    void accessTokenCannotBeUsedToRefresh() throws Exception {
        register("testuser", "CorrectHorse123!");
        HttpResponse<String> loginResp = login("testuser", "CorrectHorse123!");
        String accessToken = mapper.readTree(loginResp.body()).get("access_token").asText();
        HttpResponse<String> resp = post("/api/v1/auth/refresh", Map.of("refresh_token", accessToken));
        assertEquals(401, resp.statusCode());
    }

    @Test
    void securityHeadersPresent() throws Exception {
        HttpResponse<String> resp = get("/health", null);
        assertEquals("nosniff", resp.headers().firstValue("X-Content-Type-Options").orElse(null));
        assertEquals("DENY", resp.headers().firstValue("X-Frame-Options").orElse(null));
        assertEquals("no-store", resp.headers().firstValue("Cache-Control").orElse(null));
    }

    @Test
    void loginThrottledAfterLimit() throws Exception {
        // NFR-5: 11th login attempt within a minute should be throttled (limit=10).
        register("ratelimited", "GoodPassw0rd!");
        for (int i = 0; i < 10; i++) {
            login("ratelimited", "wrongpassword");
        }
        assertEquals(429, login("ratelimited", "wrongpassword").statusCode());
    }

    @Test
    void registerThrottledAfterLimit() throws Exception {
        // NFR-5: 6th register attempt within a minute should be throttled (limit=5).
        for (int i = 0; i < 5; i++) {
            register("user" + i, "GoodPassw0rd!");
        }
        assertEquals(429, register("user5", "GoodPassw0rd!").statusCode());
    }
}
