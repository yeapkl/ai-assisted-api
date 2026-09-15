package app;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
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
 * Integration test suite (JUnit 5 + java.net.http.HttpClient, no external test
 * framework needed). Covers FR-1..FR-7 and the security-relevant behaviors from
 * NFR-1, NFR-4, NFR-5, NFR-6, NFR-7 against a real running server.
 */
class ApiIntegrationTest {

    private static Store store;
    private static RateLimiter rateLimiter;
    private static HttpServer server;
    private static HttpClient client;
    private static String baseUrl;

    @BeforeAll
    static void startServer() throws IOException {
        Config config = new Config(Map.of(
                "JWT_SECRET_KEY", "test-secret-key-at-least-32-characters-long",
                "APP_ENV", "development"));
        store = new Store();
        rateLimiter = new RateLimiter();
        server = new ApiServer(config, store, rateLimiter).start(0);
        baseUrl = "http://localhost:" + server.getAddress().getPort();
        client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    }

    @AfterAll
    static void stopServer() {
        server.stop(0);
    }

    @BeforeEach
    void resetState() {
        store.clear();
        rateLimiter.clear();
    }

    private HttpResponse<String> post(String path, Map<String, String> body) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(JsonUtil.writeObject(body)))
                .build();
        return client.send(req, HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> get(String path, String authorizationHeader) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(baseUrl + path)).GET();
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
        assertEquals(Map.of("status", "ok"), JsonUtil.parseFlatObject(resp.body()));
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
        Map<String, String> tokens = JsonUtil.parseFlatObject(loginResp.body());
        assertNotNull(tokens.get("access_token"));
        assertNotNull(tokens.get("refresh_token"));

        HttpResponse<String> helloResp = get("/api/v1/hello", "Bearer " + tokens.get("access_token"));
        assertEquals(200, helloResp.statusCode());
        Map<String, String> body = JsonUtil.parseFlatObject(helloResp.body());
        assertEquals("Hello, bob!", body.get("message"));
        assertNotNull(body.get("server_time_utc"));

        Instant ts = Instant.parse(body.get("server_time_utc"));
        assertTrue(Math.abs(Duration.between(ts, Instant.now()).toSeconds()) < 10);
    }

    @Test
    void rejectsTamperedToken() throws Exception {
        register("testuser", "CorrectHorse123!");
        HttpResponse<String> loginResp = login("testuser", "CorrectHorse123!");
        String token = JsonUtil.parseFlatObject(loginResp.body()).get("access_token");
        assertEquals(401, get("/api/v1/hello", "Bearer " + token + "xx").statusCode());
    }

    @Test
    void refreshTokenCannotAccessProtectedRoute() throws Exception {
        register("testuser", "CorrectHorse123!");
        HttpResponse<String> loginResp = login("testuser", "CorrectHorse123!");
        String refreshToken = JsonUtil.parseFlatObject(loginResp.body()).get("refresh_token");
        assertEquals(401, get("/api/v1/hello", "Bearer " + refreshToken).statusCode());
    }

    @Test
    void duplicateRegistrationRejected() throws Exception {
        register("dup", "GoodPassw0rd!");
        assertEquals(400, register("dup", "AnotherPassw0rd!").statusCode());
    }

    @Test
    void shortPasswordRejected() throws Exception {
        assertEquals(422, register("shortpw", "short").statusCode());
    }

    @Test
    void invalidUsernameCharactersRejected() throws Exception {
        assertEquals(422, register("bad name!", "GoodPassw0rd!").statusCode());
    }

    @Test
    void malformedJsonRejected() throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + "/api/v1/auth/login"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("not-json"))
                .build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        assertTrue(resp.statusCode() == 400 || resp.statusCode() == 422);
    }

    @Test
    void loginWrongPasswordReturns401() throws Exception {
        register("carol", "GoodPassw0rd!");
        assertEquals(401, login("carol", "wrongpassword").statusCode());
    }

    @Test
    void noUserEnumerationSignal() throws Exception {
        // NFR-4: wrong-password and unknown-user errors must be identical.
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
        String refreshToken = JsonUtil.parseFlatObject(loginResp.body()).get("refresh_token");
        HttpResponse<String> resp = post("/api/v1/auth/refresh", Map.of("refresh_token", refreshToken));
        assertEquals(200, resp.statusCode());
        assertNotNull(JsonUtil.parseFlatObject(resp.body()).get("access_token"));
    }

    @Test
    void accessTokenCannotBeUsedToRefresh() throws Exception {
        // A refresh token must not double as an access token.
        register("testuser", "CorrectHorse123!");
        HttpResponse<String> loginResp = login("testuser", "CorrectHorse123!");
        String accessToken = JsonUtil.parseFlatObject(loginResp.body()).get("access_token");
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
}
