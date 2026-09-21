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

/**
 * Dedicated QA test for the developer-flagged gap: {@code JwtAuthFilter}
 * (src/main/java/com/apitest/filter/JwtAuthFilter.java) validates the OAuth
 * access token's signature/expiry via {@code oauthJwtDecoder}, but does
 * <b>not</b> check its {@code aud} claim, unlike {@code mcp-server}'s
 * resource-server config (docs/requirements/mcp-server.md NFR-4). This test
 * mints a real, validly-signed access token whose {@code aud} is something
 * other than {@code mcp-server} (this Authorization Server instance is
 * configured, via {@code app.oauth.resource-audience}, to stamp a
 * completely different value) and checks whether this API's own
 * {@code GET /api/v1/hello} accepts it anyway.
 * <p>
 * This is a real finding either way, per the handoff note - the result is
 * recorded in the QA report, not silently treated as pass/fail against a
 * specific expectation, since neither hello-world-api.md nor mcp-server.md
 * explicitly requires hello-world-api's own endpoints to check audience
 * (only mcp-server's NFR-4 does).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "app.jwt-secret-key=qa-crossaud-suite-secret-key-at-least-32-characters",
        "app.oauth.signing-key-secret=qa-crossaud-suite-signing-key-at-least-32-chars",
        "app.oauth.client-secret=qa-crossaud-suite-client-secret-at-least-32-chars",
        "app.oauth.redirect-uris=http://127.0.0.1:8765/callback",
        // Deliberately NOT "mcp-server" - simulates a token minted for some
        // other, unrelated resource server that happens to trust the same AS.
        "app.oauth.resource-audience=some-completely-different-resource-server"
})
class QaOAuthCrossAudienceHelloEndpointTest {

    private static final String CLIENT_ID = "mcp-server";
    private static final String CLIENT_SECRET = "qa-crossaud-suite-client-secret-at-least-32-chars";
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
    void oauthTokenAudiencedForAnotherResourceServer_calledAgainstOwnHelloEndpoint_documentActualBehavior()
            throws Exception {
        String username = "crossauduser";
        String password = "CrossAudPassw0rd!";
        registerUser(username, password);

        String verifier = "cross-audience-test-verifier-value-must-be-at-least-43-chars";
        String code = fullLoginAndGetCode(username, password, verifier, "cross-aud-state");

        String form = "grant_type=authorization_code&code=" + urlEncode(code)
                + "&redirect_uri=" + urlEncode(REDIRECT_URI)
                + "&client_id=" + urlEncode(CLIENT_ID) + "&client_secret=" + urlEncode(CLIENT_SECRET)
                + "&code_verifier=" + urlEncode(verifier);
        HttpResponse<String> tokenResp = post(url("/oauth2/token"), form);
        assertEquals(200, tokenResp.statusCode(), tokenResp.body());
        String accessToken = mapper.readTree(tokenResp.body()).get("access_token").asText();

        // Sanity: confirm the token really does carry the "wrong" audience,
        // so a PASS here can't be dismissed as "the aud claim was never set".
        JsonNode claims = decodeJwtClaims(accessToken);
        assertEquals("some-completely-different-resource-server",
                claims.get("aud").isArray() ? claims.get("aud").get(0).asText() : claims.get("aud").asText());

        HttpResponse<String> helloResp = client.send(
                HttpRequest.newBuilder(URI.create(url("/api/v1/hello")))
                        .header("Authorization", "Bearer " + accessToken)
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());

        // No assertEquals on status here on purpose: this test's job is to
        // observe and record actual behavior (see class Javadoc / QA report),
        // not enforce a specific contract that no requirements doc states for
        // hello-world-api's own endpoints. See docs/qa/hello-world-api-report.md
        // for what was actually observed on this run and why it matters.
        System.out.println("QA FINDING (JwtAuthFilter aud check): GET /api/v1/hello with a validly-signed "
                + "OAuth token whose aud=[some-completely-different-resource-server] returned HTTP "
                + helloResp.statusCode() + " body=" + helloResp.body());
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
