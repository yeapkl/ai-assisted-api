package com.apitest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Developer sanity test (not QA's suite) for the QA-flagged gap fix
 * (2026-09-21): {@code /login}, {@code /oauth2/token}, and
 * {@code /oauth2/authorize} now have Bucket4j rate limiting, reusing
 * {@code RateLimitFilter} exactly (see its class Javadoc). Each test method
 * in this class uses its own throwaway session/user so the three limits
 * (and the pre-existing {@code /api/v1/auth/*} ones) can be exercised
 * independently within one shared Spring context without tripping each
 * other early.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "app.jwt-secret-key=oauth-ratelimit-smoke-secret-key-at-least-32-chars",
        "app.oauth.signing-key-secret=oauth-ratelimit-smoke-signing-key-at-least-32-chars",
        "app.oauth.client-secret=oauth-ratelimit-smoke-client-secret-at-least-32-chars",
        "app.oauth.redirect-uris=http://127.0.0.1:8765/callback"
})
class OAuthRateLimitSmokeTest {

    private static final String CLIENT_ID = "mcp-server";
    private static final String REDIRECT_URI = "http://127.0.0.1:8765/callback";

    @LocalServerPort
    private int port;

    private final ObjectMapper mapper = new ObjectMapper();
    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    @Test
    void login_blockedAfter10PostsPerMinute_matchingExistingAuthLoginStrictness() throws Exception {
        HttpResponse<String> loginPage = client.send(
                HttpRequest.newBuilder(URI.create(url("/login"))).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        String sessionCookie = extractSessionCookie(loginPage);
        assertNotNull(sessionCookie, "expected a JSESSIONID cookie from GET /login");
        String csrf = extractCsrfToken(loginPage.body());
        assertNotNull(csrf);

        for (int i = 0; i < 10; i++) {
            HttpResponse<String> resp = postLogin(sessionCookie, csrf, "nonexistent-user", "wrong-password");
            assertEquals(200, resp.statusCode(), "attempt " + i + " should re-render (bad creds), not be throttled");
        }
        HttpResponse<String> eleventh = postLogin(sessionCookie, csrf, "nonexistent-user", "wrong-password");
        assertEquals(429, eleventh.statusCode(), "11th POST /login within 60s must be throttled");
    }

    @Test
    void login_rateLimitDoesNotShareABucketWithApiV1AuthLogin() throws Exception {
        // Exhaust the NEW /login bucket...
        HttpResponse<String> loginPage = client.send(
                HttpRequest.newBuilder(URI.create(url("/login"))).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        String sessionCookie = extractSessionCookie(loginPage);
        String csrf = extractCsrfToken(loginPage.body());
        for (int i = 0; i < 10; i++) {
            postLogin(sessionCookie, csrf, "isolation-check-user", "wrong-password");
        }
        assertEquals(429, postLogin(sessionCookie, csrf, "isolation-check-user", "wrong-password").statusCode(),
                "the new /login bucket should now be exhausted");

        // ...and confirm the pre-existing, separate /api/v1/auth/login
        // bucket (NFR-5, 10/60s) is completely unaffected - same process,
        // same client IP, different endpoint key.
        HttpResponse<String> jsonLogin = client.send(
                HttpRequest.newBuilder(URI.create(url("/api/v1/auth/login")))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(
                                "{\"username\":\"isolation-check-user\",\"password\":\"wrong-password\"}"))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(401, jsonLogin.statusCode(),
                "/api/v1/auth/login must not be throttled just because the new /login bucket is exhausted");
    }

    @Test
    void oauth2Token_blockedAfter20RequestsPerMinute() throws Exception {
        String form = "grant_type=authorization_code&code=never-issued&redirect_uri=" + urlEncode(REDIRECT_URI)
                + "&client_id=" + urlEncode(CLIENT_ID) + "&client_secret=irrelevant"
                + "&code_verifier=" + urlEncode("irrelevant-verifier-value-that-is-at-least-43-characters-long");
        for (int i = 0; i < 20; i++) {
            HttpResponse<String> resp = postToken(form);
            assertNotEquals(429, resp.statusCode(), "attempt " + i + " should not yet be throttled: " + resp.body());
        }
        HttpResponse<String> twentyFirst = postToken(form);
        assertEquals(429, twentyFirst.statusCode(), "21st POST /oauth2/token within 60s must be throttled");
    }

    @Test
    void oauth2Authorize_blockedAfter30RequestsPerMinute() throws Exception {
        String authorizeUrl = url("/oauth2/authorize") + "?response_type=code&client_id=" + CLIENT_ID
                + "&redirect_uri=" + urlEncode(REDIRECT_URI) + "&code_challenge=abc"
                + "&code_challenge_method=S256&state=rl-state&scope=hello.read";
        for (int i = 0; i < 30; i++) {
            HttpResponse<Void> resp = client.send(HttpRequest.newBuilder(URI.create(authorizeUrl)).GET().build(),
                    HttpResponse.BodyHandlers.discarding());
            assertNotEquals(429, resp.statusCode(), "attempt " + i + " should not yet be throttled");
        }
        HttpResponse<Void> thirtyFirst = client.send(HttpRequest.newBuilder(URI.create(authorizeUrl)).GET().build(),
                HttpResponse.BodyHandlers.discarding());
        assertEquals(429, thirtyFirst.statusCode(), "31st GET /oauth2/authorize within 60s must be throttled");
    }

    private HttpResponse<String> postLogin(String cookie, String csrf, String username, String password)
            throws Exception {
        String form = "username=" + urlEncode(username) + "&password=" + urlEncode(password)
                + "&_csrf=" + urlEncode(csrf);
        return client.send(
                HttpRequest.newBuilder(URI.create(url("/login")))
                        .header("Cookie", cookie)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(form))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> postToken(String form) throws Exception {
        return client.send(
                HttpRequest.newBuilder(URI.create(url("/oauth2/token")))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(form))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static String extractSessionCookie(HttpResponse<?> response) {
        return response.headers().allValues("Set-Cookie").stream()
                .filter(c -> c.startsWith("JSESSIONID"))
                .map(c -> c.split(";", 2)[0])
                .findFirst()
                .orElse(null);
    }

    private static String extractCsrfToken(String html) {
        Matcher m = Pattern.compile("name=\"_csrf\" value=\"([^\"]+)\"").matcher(html);
        return m.find() ? m.group(1) : null;
    }

    private static String urlEncode(String value) {
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
