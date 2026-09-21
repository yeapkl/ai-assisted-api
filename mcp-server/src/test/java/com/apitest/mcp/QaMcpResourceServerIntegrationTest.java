package com.apitest.mcp;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Independent, end-to-end QA verification of mcp-server's OAuth 2.1
 * resource-server behavior (docs/requirements/mcp-server.md FR-1, FR-2,
 * FR-3, FR-5, FR-7, FR-8, NFR-1..NFR-7), against a REAL, separately running
 * hello-world-api instance - not mocked - per the QA task's instruction
 * that this deserves a real integration test.
 * <p>
 * <b>Prerequisite (see docs/qa/mcp-server-report.md for the exact command):
 * </b> a real hello-world-api instance must already be running and
 * reachable at the URL given by the {@code qa.hello-api.base-url} system
 * property (default {@code http://localhost:18000}), with its OAuth
 * Authorization Server enabled, {@code app.oauth.resource-audience=mcp-server},
 * and (for the real expired-token test) a short
 * {@code OAUTH_ACCESS_TOKEN_EXPIRE_MINUTES=1}. mcp-server itself is booted
 * as a real, in-process Spring context (RANDOM_PORT) pointed at that
 * instance - this test only stubs nothing.
 * <p>
 * Tests run in a fixed order ({@code @Order}) purely so the one genuinely
 * slow test (real-time token expiry, ~2 minutes) runs last and the fast
 * tests fail fast first.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "oauth.resource-audience=mcp-server",
        "oauth.issuer-uri=${qa.hello-api.base-url:http://localhost:18000}",
        "api.base-url=${qa.hello-api.base-url:http://localhost:18000}"
})
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class QaMcpResourceServerIntegrationTest {

    private static final String HELLO_API_BASE_URL =
            System.getProperty("qa.hello-api.base-url", "http://localhost:18000");

    @LocalServerPort
    private int mcpPort;

    private static final ObjectMapper mapper = new ObjectMapper();
    private static final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    private static String validAccessToken;

    @BeforeAll
    static void verifyHelloApiIsUp() throws Exception {
        HttpResponse<String> health = client.send(
                HttpRequest.newBuilder(URI.create(HELLO_API_BASE_URL + "/health")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, health.statusCode(),
                "This suite requires a real hello-world-api running at " + HELLO_API_BASE_URL
                        + " - see docs/qa/mcp-server-report.md for the exact startup command");
    }

    private String mcpUrl() {
        return "http://localhost:" + mcpPort + "/mcp";
    }

    // ---------- FR-1: tools/list, and NFR-5 tool-schema regression check ----------

    @Test
    @Order(1)
    void fr1_toolsList_exposesExactlyTheThreeExpectedTools_andNoTokenArgOnGetHelloGreeting() throws Exception {
        JsonNode result = callMcp(Map.of("jsonrpc", "2.0", "id", 1, "method", "tools/list", "params", Map.of()), null);
        JsonNode tools = result.get("result").get("tools");
        assertTrue(tools.isArray());

        boolean hasCheckHealth = false, hasRegister = false, hasGreeting = false, hasLogin = false, hasRefresh = false;
        for (JsonNode tool : tools) {
            String name = tool.get("name").asText();
            switch (name) {
                case "check_api_health" -> hasCheckHealth = true;
                case "register_user" -> hasRegister = true;
                case "get_hello_greeting" -> {
                    hasGreeting = true;
                    // FR-5: no LLM-visible token/credential argument at all.
                    JsonNode props = tool.get("inputSchema").path("properties");
                    assertTrue(props.isMissingNode() || props.size() == 0,
                            "get_hello_greeting must take no arguments (FR-5): " + props);
                }
                case "login" -> hasLogin = true;
                case "refresh_access_token" -> hasRefresh = true;
                default -> { }
            }
        }
        assertTrue(hasCheckHealth, "check_api_health must be present");
        assertTrue(hasRegister, "register_user must be present");
        assertTrue(hasGreeting, "get_hello_greeting must be present");
        assertFalse(hasLogin, "FR-4: login tool must be removed");
        assertFalse(hasRefresh, "FR-6: refresh_access_token tool must be removed");
    }

    // ---------- FR-2/FR-3/NFR-7: unprotected tools work with zero Authorization header ----------

    @Test
    @Order(2)
    void fr2nfr7_checkApiHealth_worksWithNoAuthorizationHeader() throws Exception {
        JsonNode result = callMcp(Map.of("jsonrpc", "2.0", "id", 2, "method", "tools/call",
                "params", Map.of("name", "check_api_health", "arguments", Map.of())), null);
        assertFalse(result.has("error"), "unexpected JSON-RPC error: " + result);
        String text = firstContentText(result);
        assertTrue(text.contains("status") || text.contains("ok") || text.toLowerCase().contains("status"),
                "expected a real health body, got: " + text);
    }

    @Test
    @Order(3)
    void fr3nfr7_registerUser_worksWithNoAuthorizationHeader_realUpstreamCall() throws Exception {
        String username = "mcp_qa_user_" + System.nanoTime();
        JsonNode result = callMcp(Map.of("jsonrpc", "2.0", "id", 3, "method", "tools/call",
                "params", Map.of("name", "register_user", "arguments",
                        Map.of("username", username, "password", "McpQaPassw0rd!"))), null);
        assertFalse(result.has("error"), "unexpected JSON-RPC error: " + result);
        String text = firstContentText(result);
        assertFalse(text.contains("\"http_status\":4"), "registration should have succeeded, got: " + text);
    }

    // ---------- FR-7/NFR-3: 401 + WWW-Authenticate on protected tool without/garbage token ----------

    @Test
    @Order(4)
    void fr7nfr3_getHelloGreeting_noAuthorizationHeader_returnsHttp401WithWwwAuthenticate() throws Exception {
        HttpResponse<String> resp = rawMcpCall(getHelloGreetingBody(4), null);
        assertEquals(401, resp.statusCode(), "must be a real HTTP 401, not a bare JSON-RPC error");
        assertTrue(resp.headers().firstValue("WWW-Authenticate").isPresent(), "NFR-3: WWW-Authenticate header required");
        assertTrue(resp.headers().firstValue("WWW-Authenticate").get().contains("oauth-protected-resource"));
    }

    @Test
    @Order(5)
    void fr7_getHelloGreeting_garbageToken_returnsHttp401WithWwwAuthenticate() throws Exception {
        HttpResponse<String> resp = rawMcpCall(getHelloGreetingBody(5), "Bearer this.is.not-a-jwt-at-all");
        assertEquals(401, resp.statusCode());
        assertTrue(resp.headers().firstValue("WWW-Authenticate").isPresent());
    }

    // ---------- NFR-2: unrelated-key token rejected ----------

    @Test
    @Order(6)
    void nfr2_getHelloGreeting_validlyStructuredTokenSignedByUnrelatedKey_returns401() throws Exception {
        String forgedToken = mintSelfSignedJwt(HELLO_API_BASE_URL, "mcp-server", "attacker", 300);
        HttpResponse<String> resp = rawMcpCall(getHelloGreetingBody(6), "Bearer " + forgedToken);
        assertEquals(401, resp.statusCode(), "a syntactically valid JWT signed by an unrelated/unknown key must be rejected");
        assertTrue(resp.headers().firstValue("WWW-Authenticate").isPresent());
    }

    // ---------- Happy path: real valid token, real call-through to hello-world-api ----------

    @Test
    @Order(7)
    void fr5_getHelloGreeting_validCorrectlyAudiencedToken_returnsRealGreetingFromLiveHelloApi() throws Exception {
        validAccessToken = mintRealAccessTokenFromHelloApi();
        assertNotNull(validAccessToken);

        HttpResponse<String> resp = rawMcpCall(getHelloGreetingBody(7), "Bearer " + validAccessToken);
        assertEquals(200, resp.statusCode(), resp.body());
        JsonNode result = mapper.readTree(resp.body());
        String text = firstContentText(result);
        assertTrue(text.contains("Hello,"), "expected a real greeting from hello-world-api, got: " + text);
        assertTrue(text.contains("server_time_utc"));
    }

    // ---------- FR-8: RFC 9728 protected-resource metadata ----------

    @Test
    @Order(8)
    void fr8_protectedResourceMetadata_unauthenticated200WithRequiredFields() throws Exception {
        HttpResponse<String> resp = client.send(
                HttpRequest.newBuilder(URI.create("http://localhost:" + mcpPort + "/.well-known/oauth-protected-resource"))
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode());
        JsonNode body = mapper.readTree(resp.body());
        assertNotNull(body.get("resource"));
        assertTrue(body.get("authorization_servers").isArray());
        assertTrue(body.get("authorization_servers").size() > 0);
    }

    // ---------- Slow, genuinely real-time expiry test (run last) ----------

    @Test
    @Order(99)
    void nfr_expiredToken_realTimeExpiry_rejectedWith401() throws Exception {
        // OAUTH_ACCESS_TOKEN_EXPIRE_MINUTES=1 on the background hello-world-api
        // instance (see docs/qa/mcp-server-report.md for the launch command) +
        // the default resource-server JwtTimestampValidator's 60s clock skew
        // means a token needs >120s to be unambiguously expired everywhere.
        String shortLivedToken = mintRealAccessTokenFromHelloApi();
        Thread.sleep(Duration.ofSeconds(130).toMillis());

        HttpResponse<String> resp = rawMcpCall(getHelloGreetingBody(99), "Bearer " + shortLivedToken);
        assertEquals(401, resp.statusCode(), "a genuinely time-expired access token must be rejected");
        assertTrue(resp.headers().firstValue("WWW-Authenticate").isPresent());
    }

    // ---------- Helpers ----------

    private static Map<String, Object> getHelloGreetingBody(int id) {
        return Map.of("jsonrpc", "2.0", "id", id, "method", "tools/call",
                "params", Map.of("name", "get_hello_greeting", "arguments", Map.of()));
    }

    private JsonNode callMcp(Map<String, Object> body, String authHeader) throws Exception {
        HttpResponse<String> resp = rawMcpCall(body, authHeader);
        return mapper.readTree(resp.body());
    }

    private HttpResponse<String> rawMcpCall(Map<String, Object> body, String authHeader) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(mcpUrl()))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)));
        if (authHeader != null) {
            builder.header("Authorization", authHeader);
        }
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String firstContentText(JsonNode rpcResult) {
        JsonNode content = rpcResult.path("result").path("content");
        if (content.isArray() && content.size() > 0) {
            return content.get(0).path("text").asText();
        }
        return rpcResult.toString();
    }

    /** Performs a real register+authorize+login+PKCE+token round trip against the live hello-world-api. */
    private String mintRealAccessTokenFromHelloApi() throws Exception {
        String username = "mcp_qa_token_user_" + System.nanoTime();
        String password = "TokenMintPassw0rd!";
        String body = mapper.writeValueAsString(Map.of("username", username, "password", password));
        HttpResponse<String> registerResp = client.send(
                HttpRequest.newBuilder(URI.create(HELLO_API_BASE_URL + "/api/v1/auth/register"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(201, registerResp.statusCode(), registerResp.body());

        String verifier = "mcp-qa-verifier-value-" + System.nanoTime() + "-padding-to-43-chars-min!!";
        String challenge = base64UrlSha256(verifier);
        String redirectUri = "http://127.0.0.1:8765/callback";
        String authorizeUrl = HELLO_API_BASE_URL + "/oauth2/authorize?response_type=code&client_id=mcp-server"
                + "&redirect_uri=" + urlEncode(redirectUri) + "&code_challenge=" + urlEncode(challenge)
                + "&code_challenge_method=S256&state=mcp-qa-state&scope=hello.read";

        HttpResponse<Void> initial = client.send(HttpRequest.newBuilder(URI.create(authorizeUrl)).GET().build(),
                HttpResponse.BodyHandlers.discarding());
        String sessionCookie = extractSessionCookie(initial);
        assertNotNull(sessionCookie, "expected a session cookie from /oauth2/authorize");

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
        assertEquals(302, loginResult.statusCode(), "login must succeed - see mcp-qa-token-user setup");
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
        return mapper.readTree(tokenResp.body()).get("access_token").asText();
    }

    private static String mcpOauthClientSecret() {
        return System.getProperty("qa.mcp-oauth-client-secret",
                System.getenv().getOrDefault("QA_MCP_OAUTH_CLIENT_SECRET", ""));
    }

    /** NFR-2: mints a syntactically valid RS256 JWT signed by a throwaway key unrelated to hello-world-api's own. */
    private static String mintSelfSignedJwt(String issuer, String audience, String subject, int ttlSeconds)
            throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(subject)
                .issuer(issuer)
                .audience(audience)
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(ttlSeconds)))
                .claim("scope", List.of("hello.read"))
                .build();
        SignedJWT signedJwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
        signedJwt.sign(new RSASSASigner((RSAPrivateKey) keyPair.getPrivate()));
        return signedJwt.serialize();
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
