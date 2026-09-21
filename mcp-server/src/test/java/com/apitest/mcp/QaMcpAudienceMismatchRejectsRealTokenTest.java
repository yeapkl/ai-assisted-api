package com.apitest.mcp;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
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
 * NFR-4, isolating the audience check with a REAL, cryptographically valid
 * token (not a synthetic {@code Jwt} object): a genuinely valid, correctly
 * signed access token minted by the real hello-world-api instance (with
 * {@code aud=["mcp-server"]}, matching hello-world-api's own default
 * resource-audience config) is presented to a mcp-server instance that is
 * itself configured to require a DIFFERENT audience
 * ({@code oauth.resource-audience=some-other-required-audience}) - i.e.
 * from this mcp-server instance's point of view, the token names a
 * different resource. Signature, issuer, and expiry are all genuinely
 * valid; only the audience match fails. Must be rejected with 401.
 * <p>
 * This sidesteps the practical impossibility of getting hello-world-api to
 * mint two tokens with different {@code aud} values from the exact same
 * signing key without an in-process reflection hack (its RSA signing key is
 * regenerated fresh per process start, and {@code aud} is a single
 * per-process config value) - see docs/qa/mcp-server-report.md for the full
 * reasoning. Complements {@link com.apitest.mcp.security.AudienceValidatorTest}
 * (isolated unit test of the validator logic) and
 * {@link QaMcpResourceServerIntegrationTest} (correct-audience happy path).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "oauth.resource-audience=some-other-required-audience-not-mcp-server",
        "oauth.issuer-uri=${qa.hello-api.base-url:http://localhost:18000}",
        "api.base-url=${qa.hello-api.base-url:http://localhost:18000}"
})
class QaMcpAudienceMismatchRejectsRealTokenTest {

    private static final String HELLO_API_BASE_URL =
            System.getProperty("qa.hello-api.base-url", "http://localhost:18000");

    @LocalServerPort
    private int mcpPort;

    private final ObjectMapper mapper = new ObjectMapper();
    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    @Test
    void realValidTokenAudiencedForMcpServer_rejectedByInstanceRequiringADifferentAudience() throws Exception {
        String accessToken = mintRealAccessTokenFromHelloApi();

        Map<String, Object> body = Map.of("jsonrpc", "2.0", "id", 1, "method", "tools/call",
                "params", Map.of("name", "get_hello_greeting", "arguments", Map.of()));
        HttpResponse<String> resp = client.send(
                HttpRequest.newBuilder(URI.create("http://localhost:" + mcpPort + "/mcp"))
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json, text/event-stream")
                        .header("Authorization", "Bearer " + accessToken)
                        .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertEquals(401, resp.statusCode(),
                "a real, validly-signed, unexpired token whose aud=[mcp-server] must be rejected by an instance "
                        + "configured to require a different audience (NFR-4)");
        assertTrue(resp.headers().firstValue("WWW-Authenticate").isPresent());
    }

    private String mintRealAccessTokenFromHelloApi() throws Exception {
        String username = "audmis_" + (System.nanoTime() % 1000000000L);
        String password = "AudMismatchPassw0rd!";
        String registerBody = mapper.writeValueAsString(Map.of("username", username, "password", password));
        HttpResponse<String> registerResp = client.send(
                HttpRequest.newBuilder(URI.create(HELLO_API_BASE_URL + "/api/v1/auth/register"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(registerBody))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(201, registerResp.statusCode(), registerResp.body());

        String verifier = "audmismatch-verifier-" + System.nanoTime() + "-padding-to-43-chars-min!!";
        String challenge = base64UrlSha256(verifier);
        String redirectUri = "http://127.0.0.1:8765/callback";
        String authorizeUrl = HELLO_API_BASE_URL + "/oauth2/authorize?response_type=code&client_id=mcp-server"
                + "&redirect_uri=" + urlEncode(redirectUri) + "&code_challenge=" + urlEncode(challenge)
                + "&code_challenge_method=S256&state=audmismatch-state&scope=hello.read";

        HttpResponse<Void> initial = client.send(HttpRequest.newBuilder(URI.create(authorizeUrl)).GET().build(),
                HttpResponse.BodyHandlers.discarding());
        String sessionCookie = extractSessionCookie(initial);
        assertNotNull(sessionCookie);

        HttpResponse<String> loginPage = client.send(
                HttpRequest.newBuilder(URI.create(HELLO_API_BASE_URL + "/login"))
                        .header("Cookie", sessionCookie).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        String csrf = extractCsrfToken(loginPage.body());
        assertNotNull(csrf);

        String loginForm = "username=" + urlEncode(username) + "&password=" + urlEncode(password)
                + "&_csrf=" + urlEncode(csrf);
        HttpResponse<Void> loginResult = client.send(
                HttpRequest.newBuilder(URI.create(HELLO_API_BASE_URL + "/login"))
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
        String code = extractQueryParam(callbackLocation, "code");
        assertNotNull(code);

        String tokenForm = "grant_type=authorization_code&code=" + urlEncode(code)
                + "&redirect_uri=" + urlEncode(redirectUri)
                + "&client_id=mcp-server&client_secret=" + urlEncode(mcpOauthClientSecret())
                + "&code_verifier=" + urlEncode(verifier);
        HttpResponse<String> tokenResp = client.send(
                HttpRequest.newBuilder(URI.create(HELLO_API_BASE_URL + "/oauth2/token"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(tokenForm))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, tokenResp.statusCode(), tokenResp.body());
        String accessToken = mapper.readTree(tokenResp.body()).get("access_token").asText();

        // Sanity: confirm the real token really is audienced for mcp-server
        // (the CORRECT audience) - so a 401 in the actual test can only be
        // explained by this instance's own, deliberately different,
        // required-audience config, not by hello-world-api emitting a wrong aud.
        JsonNode claims = decodeJwtClaims(accessToken);
        JsonNode aud = claims.get("aud");
        String audValue = aud.isArray() ? aud.get(0).asText() : aud.asText();
        assertEquals("mcp-server", audValue);

        return accessToken;
    }

    private static String mcpOauthClientSecret() {
        return System.getProperty("qa.mcp-oauth-client-secret",
                System.getenv().getOrDefault("QA_MCP_OAUTH_CLIENT_SECRET", ""));
    }

    private JsonNode decodeJwtClaims(String jwt) throws Exception {
        String[] parts = jwt.split("\\.");
        byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
        return mapper.readTree(payload);
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
}
