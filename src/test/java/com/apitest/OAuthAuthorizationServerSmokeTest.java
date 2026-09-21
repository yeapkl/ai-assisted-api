package com.apitest;

import com.apitest.store.UserStore;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Developer smoke test for the OAuth 2.1 Authorization Server addition
 * (NFR-13..NFR-20) - NOT the deliverable test suite (QA owns that
 * independently). Sanity-checks: the RFC 8414 metadata shape, a full
 * UserStore-backed authorization_code+PKCE+token round trip via real HTTP
 * against an embedded server (same {@code java.net.http.HttpClient}
 * approach as {@link ApiIntegrationTest}), and that the issued access token
 * carries the {@code aud} claim (NFR-19).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "app.jwt-secret-key=test-secret-key-at-least-32-characters-long",
        "app.oauth.signing-key-secret=test-oauth-signing-key-smoke-test-32-chars-min",
        "app.oauth.client-secret=test-oauth-client-secret-smoke-test-32-chars-min",
        "app.oauth.redirect-uris=http://127.0.0.1:8765/callback"
})
class OAuthAuthorizationServerSmokeTest {

    @LocalServerPort
    private int port;

    @Autowired
    private UserStore userStore;

    private final ObjectMapper mapper = new ObjectMapper();
    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    @BeforeEach
    void resetState() {
        userStore.clear();
    }

    private String baseUrl(String path) {
        return "http://localhost:" + port + path;
    }

    @Test
    void metadataEndpoint_isUnauthenticatedAndHasRequiredFields() throws Exception {
        HttpResponse<String> response = client.send(
                HttpRequest.newBuilder(URI.create(baseUrl("/.well-known/oauth-authorization-server"))).GET().build(),
                HttpResponse.BodyHandlers.ofString());

        assertEquals(200, response.statusCode());
        JsonNode body = mapper.readTree(response.body());
        assertNotNull(body.get("issuer"));
        assertNotNull(body.get("authorization_endpoint"));
        assertNotNull(body.get("token_endpoint"));
        assertTrue(contains(body.get("response_types_supported"), "code"));
        assertTrue(contains(body.get("grant_types_supported"), "authorization_code"));
        assertTrue(contains(body.get("grant_types_supported"), "refresh_token"));
        assertTrue(contains(body.get("code_challenge_methods_supported"), "S256"));
    }

    @Test
    void fullAuthorizationCodePkceRoundTrip_issuesAccessTokenWithAudienceClaim() throws Exception {
        // NFR-17: register via the existing JSON endpoint, log in via the new
        // OAuth form with the SAME credentials, backed by the same UserStore.
        registerUser("alice", "S3cur3Passw0rd!");

        String verifier = "smoke-test-code-verifier-value-must-be-at-least-43-chars-long";
        String challenge = base64UrlSha256(verifier);

        String authorizeUrl = baseUrl("/oauth2/authorize") + "?response_type=code&client_id=mcp-server"
                + "&redirect_uri=http://127.0.0.1:8765/callback&code_challenge=" + challenge
                + "&code_challenge_method=S256&state=smoke-state&scope=hello.read";

        HttpResponse<Void> initial = client.send(HttpRequest.newBuilder(URI.create(authorizeUrl)).GET().build(),
                HttpResponse.BodyHandlers.discarding());
        assertEquals(302, initial.statusCode());
        String sessionCookie = extractSessionCookie(initial);
        assertNotNull(sessionCookie, "expected a JSESSIONID cookie from /oauth2/authorize");

        HttpResponse<String> loginPage = client.send(HttpRequest.newBuilder(URI.create(baseUrl("/login")))
                .header("Cookie", sessionCookie)
                .GET()
                .build(), HttpResponse.BodyHandlers.ofString());
        String csrfToken = extractCsrfToken(loginPage.body());
        assertNotNull(csrfToken, "expected a CSRF token in the rendered login form");

        String loginForm = "username=alice&password=" + urlEncode("S3cur3Passw0rd!") + "&_csrf=" + urlEncode(csrfToken);
        HttpResponse<Void> loginResult = client.send(HttpRequest.newBuilder(URI.create(baseUrl("/login")))
                .header("Cookie", sessionCookie)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(loginForm))
                .build(), HttpResponse.BodyHandlers.discarding());
        assertEquals(302, loginResult.statusCode(), "valid credentials must redirect (NFR-14), not re-render");
        String continueLocation = loginResult.headers().firstValue("Location").orElseThrow();
        // Spring Security rotates the session ID on successful authentication
        // (session-fixation protection) - pick up the new cookie if one was set.
        String postLoginCookie = extractSessionCookie(loginResult);
        String activeCookie = postLoginCookie != null ? postLoginCookie : sessionCookie;

        HttpResponse<Void> continued = client.send(HttpRequest.newBuilder(URI.create(continueLocation))
                .header("Cookie", activeCookie)
                .GET()
                .build(), HttpResponse.BodyHandlers.discarding());
        assertEquals(302, continued.statusCode());
        String callbackLocation = continued.headers().firstValue("Location").orElseThrow();
        assertTrue(callbackLocation.startsWith("http://127.0.0.1:8765/callback"));
        assertTrue(callbackLocation.contains("state=smoke-state"));

        String code = extractQueryParam(callbackLocation, "code");
        assertNotNull(code);

        String tokenForm = "grant_type=authorization_code&code=" + urlEncode(code)
                + "&redirect_uri=" + urlEncode("http://127.0.0.1:8765/callback")
                + "&client_id=mcp-server&client_secret=" + urlEncode("test-oauth-client-secret-smoke-test-32-chars-min")
                + "&code_verifier=" + urlEncode(verifier);
        HttpResponse<String> tokenResponse = client.send(HttpRequest.newBuilder(URI.create(baseUrl("/oauth2/token")))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(tokenForm))
                .build(), HttpResponse.BodyHandlers.ofString());

        assertEquals(200, tokenResponse.statusCode(), tokenResponse.body());
        JsonNode tokenBody = mapper.readTree(tokenResponse.body());
        assertEquals("Bearer", tokenBody.get("token_type").asText());
        assertNotNull(tokenBody.get("access_token"));
        assertNotNull(tokenBody.get("refresh_token"));

        // NFR-19: the access token carries an `aud` claim naming mcp-server.
        String accessToken = tokenBody.get("access_token").asText();
        JsonNode claims = decodeJwtClaims(accessToken);
        assertEquals("alice", claims.get("sub").asText());
        assertTrue(audienceContains(claims.get("aud"), "mcp-server"));
    }

    @Test
    void tokenEndpoint_wrongCodeVerifier_returns400InvalidGrant() throws Exception {
        registerUser("bob", "AnotherPassw0rd!");
        String verifier = "smoke-test-code-verifier-value-must-be-at-least-43-chars-long";
        String challenge = base64UrlSha256(verifier);

        String authorizeUrl = baseUrl("/oauth2/authorize") + "?response_type=code&client_id=mcp-server"
                + "&redirect_uri=http://127.0.0.1:8765/callback&code_challenge=" + challenge
                + "&code_challenge_method=S256&state=s2&scope=hello.read";
        HttpResponse<Void> initial = client.send(HttpRequest.newBuilder(URI.create(authorizeUrl)).GET().build(),
                HttpResponse.BodyHandlers.discarding());
        String sessionCookie = extractSessionCookie(initial);

        HttpResponse<String> loginPage = client.send(HttpRequest.newBuilder(URI.create(baseUrl("/login")))
                .header("Cookie", sessionCookie).GET().build(), HttpResponse.BodyHandlers.ofString());
        String csrfToken = extractCsrfToken(loginPage.body());

        String loginForm = "username=bob&password=" + urlEncode("AnotherPassw0rd!") + "&_csrf=" + urlEncode(csrfToken);
        HttpResponse<Void> loginResult = client.send(HttpRequest.newBuilder(URI.create(baseUrl("/login")))
                .header("Cookie", sessionCookie)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(loginForm))
                .build(), HttpResponse.BodyHandlers.discarding());
        String continueLocation = loginResult.headers().firstValue("Location").orElseThrow();
        String postLoginCookie = extractSessionCookie(loginResult);
        String activeCookie = postLoginCookie != null ? postLoginCookie : sessionCookie;
        HttpResponse<Void> continued = client.send(HttpRequest.newBuilder(URI.create(continueLocation))
                .header("Cookie", activeCookie).GET().build(), HttpResponse.BodyHandlers.discarding());
        String callbackLocation = continued.headers().firstValue("Location").orElseThrow();
        String code = extractQueryParam(callbackLocation, "code");

        String tokenForm = "grant_type=authorization_code&code=" + urlEncode(code)
                + "&redirect_uri=" + urlEncode("http://127.0.0.1:8765/callback")
                + "&client_id=mcp-server&client_secret=" + urlEncode("test-oauth-client-secret-smoke-test-32-chars-min")
                + "&code_verifier=" + urlEncode("this-is-the-wrong-verifier-value-1234567890ABCDEFGH");
        HttpResponse<String> tokenResponse = client.send(HttpRequest.newBuilder(URI.create(baseUrl("/oauth2/token")))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(tokenForm))
                .build(), HttpResponse.BodyHandlers.ofString());

        assertEquals(400, tokenResponse.statusCode());
        JsonNode body = mapper.readTree(tokenResponse.body());
        assertEquals("invalid_grant", body.get("error").asText());
    }

    @Test
    void loginForm_invalidCredentials_reRendersWithGenericErrorAndDoesNotRedirect() throws Exception {
        registerUser("carol", "YetAnotherPassw0rd!");
        String verifier = "smoke-test-code-verifier-value-must-be-at-least-43-chars-long";
        String challenge = base64UrlSha256(verifier);
        String authorizeUrl = baseUrl("/oauth2/authorize") + "?response_type=code&client_id=mcp-server"
                + "&redirect_uri=http://127.0.0.1:8765/callback&code_challenge=" + challenge
                + "&code_challenge_method=S256&state=s3&scope=hello.read";
        HttpResponse<Void> initial = client.send(HttpRequest.newBuilder(URI.create(authorizeUrl)).GET().build(),
                HttpResponse.BodyHandlers.discarding());
        String sessionCookie = extractSessionCookie(initial);

        HttpResponse<String> loginPage = client.send(HttpRequest.newBuilder(URI.create(baseUrl("/login")))
                .header("Cookie", sessionCookie).GET().build(), HttpResponse.BodyHandlers.ofString());
        String csrfToken = extractCsrfToken(loginPage.body());

        String loginForm = "username=carol&password=" + urlEncode("wrong-password") + "&_csrf=" + urlEncode(csrfToken);
        HttpResponse<String> loginResult = client.send(HttpRequest.newBuilder(URI.create(baseUrl("/login")))
                .header("Cookie", sessionCookie)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(loginForm))
                .build(), HttpResponse.BodyHandlers.ofString());

        assertEquals(200, loginResult.statusCode(), "invalid credentials must re-render, not redirect (NFR-14)");
        assertTrue(loginResult.body().contains("Invalid username or password"));
        assertTrue(loginResult.body().toLowerCase().contains("carol") == false,
                "generic error must not echo/confirm the username");
    }

    private void registerUser(String username, String password) throws Exception {
        String body = mapper.writeValueAsString(Map.of("username", username, "password", password));
        HttpResponse<String> response = client.send(HttpRequest.newBuilder(URI.create(baseUrl("/api/v1/auth/register")))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(201, response.statusCode(), response.body());
    }

    private static boolean contains(JsonNode arrayNode, String value) {
        if (arrayNode == null || !arrayNode.isArray()) {
            return false;
        }
        for (JsonNode node : arrayNode) {
            if (value.equals(node.asText())) {
                return true;
            }
        }
        return false;
    }

    private static boolean audienceContains(JsonNode audNode, String value) {
        if (audNode == null) {
            return false;
        }
        if (audNode.isArray()) {
            return contains(audNode, value);
        }
        return value.equals(audNode.asText());
    }

    private static String extractSessionCookie(HttpResponse<?> response) {
        return response.headers().allValues("Set-Cookie").stream()
                .filter(c -> c.startsWith("JSESSIONID"))
                .map(c -> c.split(";", 2)[0])
                .findFirst()
                .orElse(null);
    }

    private static String extractCsrfToken(String html) {
        Matcher matcher = Pattern.compile("name=\"_csrf\" value=\"([^\"]+)\"").matcher(html);
        return matcher.find() ? matcher.group(1) : null;
    }

    private static String extractQueryParam(String url, String name) {
        Matcher matcher = Pattern.compile("[?&]" + name + "=([^&]+)").matcher(url);
        return matcher.find() ? matcher.group(1) : null;
    }

    private static String urlEncode(String value) {
        return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
    }

    private static String base64UrlSha256(String verifier) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(verifier.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    private JsonNode decodeJwtClaims(String jwt) throws Exception {
        String[] parts = jwt.split("\\.");
        byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
        return mapper.readTree(payload);
    }
}
