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
import java.nio.charset.StandardCharsets;
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
 * Developer sanity test (not QA's suite) for the QA-flagged gap fix
 * (2026-09-21, see docs/qa/hello-world-api-report.md Finding 1): confirms
 * the real, end-to-end, single-client flow this whole OAuth feature exists
 * for is NOT broken by adding audience enforcement to this app's own
 * {@code GET /api/v1/hello} - the exact regression risk called out in the
 * fix task. Uses the SAME real HTTP approach as
 * {@code OAuthAuthorizationServerSmokeTest} (default config - no property
 * overrides - so this exercises exactly what a real deployment does).
 * <p>
 * Traced {@code HelloApiTools.getHelloGreeting()} (mcp-server) before this
 * fix: it forwards the exact access token it received (audienced for
 * {@code mcp-server}) straight through to this app's own
 * {@code GET /api/v1/hello} - the same token, not a second one. So the
 * realistic token this endpoint must keep accepting is one whose {@code aud}
 * contains {@code mcp-server} (and, after this fix, also
 * {@code hello-world-api} - see {@code AuthorizationServerConfig.jwtCustomizer}).
 * A dedicated, isolated unit test of the actual rejection logic (a token
 * lacking this app's own audience) lives in
 * {@code com.apitest.oauth.AudienceValidatorTest} - see its Javadoc for why
 * a genuinely wrong-audience *live* token can't honestly be constructed
 * against this same single-client instance.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "app.jwt-secret-key=aud-enforcement-smoke-secret-key-at-least-32-chars",
        "app.oauth.signing-key-secret=aud-enforcement-smoke-signing-key-at-least-32-chars",
        "app.oauth.client-secret=aud-enforcement-smoke-client-secret-at-least-32-chars",
        "app.oauth.redirect-uris=http://127.0.0.1:8765/callback"
})
class OAuthAudienceEnforcementSmokeTest {

    private static final String CLIENT_ID = "mcp-server";
    private static final String CLIENT_SECRET = "aud-enforcement-smoke-client-secret-at-least-32-chars";
    private static final String REDIRECT_URI = "http://127.0.0.1:8765/callback";

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

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    @Test
    void realMcpServerAudiencedToken_stillAcceptedByOwnHelloEndpoint_afterAudienceEnforcementFix() throws Exception {
        String username = "aud_ok_user";
        String password = "AudienceOkPassw0rd!";
        registerUser(username, password);

        String verifier = "aud-enforcement-smoke-verifier-must-be-at-least-43-characters!";
        String code = fullLoginAndGetCode(username, password, verifier, "aud-ok-state");

        String tokenForm = "grant_type=authorization_code&code=" + urlEncode(code)
                + "&redirect_uri=" + urlEncode(REDIRECT_URI)
                + "&client_id=" + urlEncode(CLIENT_ID) + "&client_secret=" + urlEncode(CLIENT_SECRET)
                + "&code_verifier=" + urlEncode(verifier);
        HttpResponse<String> tokenResp = post(url("/oauth2/token"), tokenForm);
        assertEquals(200, tokenResp.statusCode(), tokenResp.body());
        String accessToken = mapper.readTree(tokenResp.body()).get("access_token").asText();

        // Confirm the fix actually stamped BOTH audiences on the real token
        // (not just mcp-server as before) - this is what makes the
        // call-through case below work.
        JsonNode claims = decodeJwtClaims(accessToken);
        assertTrue(audienceContains(claims.get("aud"), "mcp-server"), "mcp-server's own check must still pass");
        assertTrue(audienceContains(claims.get("aud"), "hello-world-api"),
                "hello-world-api's own new audience check needs this");

        // The actual regression check: mcp-server's get_hello_greeting
        // forwards this exact token to GET /api/v1/hello - confirm it's
        // still accepted now that audience enforcement is in place.
        HttpResponse<String> helloResp = client.send(
                HttpRequest.newBuilder(URI.create(url("/api/v1/hello")))
                        .header("Authorization", "Bearer " + accessToken)
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, helloResp.statusCode(), helloResp.body());
        JsonNode helloBody = mapper.readTree(helloResp.body());
        assertEquals("Hello, " + username + "!", helloBody.get("message").asText());
    }

    @Test
    void oauthTokenWithNoBearerAtAll_stillRejected_regressionGuard() throws Exception {
        HttpResponse<String> resp = client.send(
                HttpRequest.newBuilder(URI.create(url("/api/v1/hello"))).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(401, resp.statusCode());
    }

    private void registerUser(String username, String password) throws Exception {
        String body = mapper.writeValueAsString(Map.of("username", username, "password", password));
        HttpResponse<String> resp = client.send(
                HttpRequest.newBuilder(URI.create(url("/api/v1/auth/register")))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(201, resp.statusCode(), resp.body());
    }

    private String fullLoginAndGetCode(String username, String password, String verifier, String state)
            throws Exception {
        String challenge = base64UrlSha256(verifier);
        String authorizeUrl = url("/oauth2/authorize") + "?response_type=code&client_id=" + CLIENT_ID
                + "&redirect_uri=" + urlEncode(REDIRECT_URI) + "&code_challenge=" + urlEncode(challenge)
                + "&code_challenge_method=S256&state=" + urlEncode(state) + "&scope=hello.read";

        HttpResponse<Void> initial = client.send(HttpRequest.newBuilder(URI.create(authorizeUrl)).GET().build(),
                HttpResponse.BodyHandlers.discarding());
        String sessionCookie = extractSessionCookie(initial);
        assertNotNull(sessionCookie);

        HttpResponse<String> loginPage = client.send(
                HttpRequest.newBuilder(URI.create(url("/login"))).header("Cookie", sessionCookie).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        String csrf = extractCsrfToken(loginPage.body());

        String loginForm = "username=" + urlEncode(username) + "&password=" + urlEncode(password)
                + "&_csrf=" + urlEncode(csrf);
        HttpResponse<Void> loginResult = client.send(
                HttpRequest.newBuilder(URI.create(url("/login")))
                        .header("Cookie", sessionCookie)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(loginForm))
                        .build(),
                HttpResponse.BodyHandlers.discarding());
        assertEquals(302, loginResult.statusCode());
        String continueLocation = loginResult.headers().firstValue("Location").orElseThrow();
        String postLoginCookie = extractSessionCookie(loginResult);
        String activeCookie = postLoginCookie != null ? postLoginCookie : sessionCookie;

        HttpResponse<Void> continued = client.send(
                HttpRequest.newBuilder(URI.create(continueLocation)).header("Cookie", activeCookie).GET().build(),
                HttpResponse.BodyHandlers.discarding());
        assertEquals(302, continued.statusCode());
        String callbackLocation = continued.headers().firstValue("Location").orElseThrow();
        return extractQueryParam(callbackLocation, "code");
    }

    private HttpResponse<String> post(String url, String form) throws Exception {
        return client.send(
                HttpRequest.newBuilder(URI.create(url))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(form))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static boolean audienceContains(JsonNode audNode, String value) {
        if (audNode == null) {
            return false;
        }
        if (audNode.isArray()) {
            for (JsonNode node : audNode) {
                if (value.equals(node.asText())) {
                    return true;
                }
            }
            return false;
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
        Matcher m = Pattern.compile("name=\"_csrf\" value=\"([^\"]+)\"").matcher(html);
        return m.find() ? m.group(1) : null;
    }

    private static String extractQueryParam(String url, String name) {
        Matcher m = Pattern.compile("[?&]" + name + "=([^&]+)").matcher(url);
        return m.find() ? m.group(1) : null;
    }

    private static String urlEncode(String value) {
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String base64UrlSha256(String verifier) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(verifier.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    private JsonNode decodeJwtClaims(String jwt) throws Exception {
        String[] parts = jwt.split("\\.");
        byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
        return mapper.readTree(payload);
    }
}
