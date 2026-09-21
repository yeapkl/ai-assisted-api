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
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Independent QA verification of the OAuth 2.1 Authorization Server addition
 * (docs/requirements/hello-world-api.md NFR-13..NFR-20). Written from
 * scratch against the requirements doc, not by reusing/importing the
 * developer's own {@code OAuthAuthorizationServerSmokeTest} - deliberately
 * covers negative/edge cases that class does not: mismatched redirect_uri,
 * missing code_verifier, authorization-code replay, unknown-username login
 * (NFR-4 parity), and the plain-PKCE rejection path.
 * <p>
 * Real HTTP against a full embedded Spring context (RANDOM_PORT), exactly
 * as this repo's existing QA suites do - no mocking of the AS itself.
 * <p>
 * {@code app.rate-limit.trust-x-forwarded-for=true} is set here (mirroring
 * {@code QaTrustedProxyRateLimitTest}'s established technique) purely so
 * this suite's many independent {@code registerUser} calls - one real user
 * per test scenario, deliberately not shared, to keep each test
 * self-contained - don't trip NFR-5's real 5/60s register rate limit
 * against each other; each call uses a distinct synthetic
 * {@code X-Forwarded-For} value. This is a test-isolation technique only,
 * not something under test here (NFR-5 itself is covered by the existing
 * QA suite).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "app.jwt-secret-key=qa-oauth-suite-secret-key-at-least-32-characters-long",
        "app.oauth.signing-key-secret=qa-oauth-suite-signing-key-at-least-32-characters",
        "app.oauth.client-secret=qa-oauth-suite-client-secret-at-least-32-characters",
        "app.oauth.redirect-uris=http://127.0.0.1:8765/callback",
        "app.oauth.resource-audience=mcp-server",
        "app.rate-limit.trust-x-forwarded-for=true"
})
class QaOAuthAuthorizationServerTest {

    private static final String CLIENT_ID = "mcp-server";
    private static final String CLIENT_SECRET = "qa-oauth-suite-client-secret-at-least-32-characters";
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
    private static final AtomicInteger forwardedForCounter = new AtomicInteger();

    @BeforeEach
    void resetState() {
        userStore.clear();
    }

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    // ---------- NFR-13: discovery metadata ----------

    @Test
    void nfr13_metadata_unauthenticated200WithAllRequiredFields() throws Exception {
        HttpResponse<String> resp = get(url("/.well-known/oauth-authorization-server"), null);
        assertEquals(200, resp.statusCode());
        assertTrue(resp.headers().firstValue("Content-Type").orElse("").contains("application/json"));

        JsonNode body = mapper.readTree(resp.body());
        assertNotNull(body.get("issuer"));
        assertFalse(body.get("issuer").asText().isBlank());
        assertNotNull(body.get("authorization_endpoint"));
        assertNotNull(body.get("token_endpoint"));
        assertTrue(jsonArrayContains(body.get("response_types_supported"), "code"));
        assertTrue(jsonArrayContains(body.get("grant_types_supported"), "authorization_code"));
        assertTrue(jsonArrayContains(body.get("grant_types_supported"), "refresh_token"));
        assertTrue(jsonArrayContains(body.get("code_challenge_methods_supported"), "S256"));
        // NFR-18: plain must not be advertised as supported.
        assertFalse(jsonArrayContains(body.get("code_challenge_methods_supported"), "plain"));
    }

    // ---------- NFR-14: HTML login form ----------

    @Test
    void nfr14_authorize_unauthenticated_endsUpAtHtmlLoginForm() throws Exception {
        String challenge = base64UrlSha256("a-verifier-that-is-at-least-forty-three-characters-long-1");
        String authorizeUrl = authorizeUrl(challenge, "state-abc");

        HttpResponse<Void> initial = client.send(
                HttpRequest.newBuilder(URI.create(authorizeUrl)).GET().build(),
                HttpResponse.BodyHandlers.discarding());
        assertEquals(302, initial.statusCode(), "unauthenticated visitor must be redirected toward /login");
        String location = initial.headers().firstValue("Location").orElseThrow();
        String sessionCookie = extractSessionCookie(initial);
        assertNotNull(sessionCookie);

        HttpResponse<String> loginPage = client.send(
                HttpRequest.newBuilder(URI.create(location.startsWith("http") ? location : url(location)))
                        .header("Cookie", sessionCookie).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, loginPage.statusCode());
        assertTrue(loginPage.headers().firstValue("Content-Type").orElse("").contains("text/html"));
        assertTrue(loginPage.body().contains("<form"));
        assertTrue(loginPage.body().contains("name=\"username\""));
        assertTrue(loginPage.body().contains("name=\"password\""));
    }

    @Test
    void nfr14_login_unknownUsername_genericErrorNoRedirect_noEnumeration() throws Exception {
        String result = attemptLoginDirectly("definitely-not-a-registered-user", "whatever-password");
        assertTrue(result.contains("Invalid username or password"));
        assertFalse(result.toLowerCase().contains("not found"));
        assertFalse(result.toLowerCase().contains("no such user"));
    }

    @Test
    void nfr14_login_wrongPassword_sameGenericErrorAsUnknownUser() throws Exception {
        registerUser("wrongpwuser", "CorrectPassw0rd!");
        String knownUserWrongPw = attemptLoginDirectly("wrongpwuser", "IncorrectPassw0rd!");
        String unknownUser = attemptLoginDirectly("no-such-user-at-all", "IncorrectPassw0rd!");
        // NFR-4's intent extended to the OAuth form: identical generic error text.
        assertEquals(extractErrorText(knownUserWrongPw), extractErrorText(unknownUser));
    }

    // ---------- NFR-17: UserStore bridge ----------

    @Test
    void nfr17_userRegisteredViaJsonEndpoint_canLoginViaOAuthFormWithSameCredentials() throws Exception {
        registerUser("bridgeduser", "BridgeMePassw0rd!");
        String verifier = "bridge-test-verifier-value-must-be-at-least-43-characters-long";
        String code = fullLoginAndGetCode("bridgeduser", "BridgeMePassw0rd!", verifier, "bridge-state");
        assertNotNull(code, "user registered via /api/v1/auth/register must be able to obtain an auth code via /oauth2/authorize+/login");

        JsonNode tokenBody = exchangeCode(code, verifier, REDIRECT_URI, CLIENT_SECRET);
        assertNotNull(tokenBody.get("access_token"));
    }

    // ---------- NFR-15/16: token endpoint happy path + refresh ----------

    @Test
    void nfr15_fullRoundTrip_issuesAccessAndRefreshTokenWithAudClaim() throws Exception {
        registerUser("roundtrip", "RoundTripPassw0rd!");
        String verifier = "roundtrip-verifier-value-must-be-at-least-43-characters-long!!";
        String code = fullLoginAndGetCode("roundtrip", "RoundTripPassw0rd!", verifier, "rt-state");

        JsonNode tokenBody = exchangeCode(code, verifier, REDIRECT_URI, CLIENT_SECRET);
        assertEquals("Bearer", tokenBody.get("token_type").asText());
        assertNotNull(tokenBody.get("access_token"));
        assertNotNull(tokenBody.get("refresh_token"));
        assertTrue(tokenBody.get("expires_in").asInt() > 0);

        JsonNode claims = decodeJwtClaims(tokenBody.get("access_token").asText());
        assertEquals("roundtrip", claims.get("sub").asText());
        assertTrue(audienceContains(claims.get("aud"), "mcp-server"));
    }

    @Test
    void nfr16_refreshTokenGrant_issuesNewAccessToken() throws Exception {
        registerUser("refresher", "RefresherPassw0rd!");
        String verifier = "refresh-grant-verifier-must-be-at-least-43-characters-long!!!";
        String code = fullLoginAndGetCode("refresher", "RefresherPassw0rd!", verifier, "rf-state");
        JsonNode tokenBody = exchangeCode(code, verifier, REDIRECT_URI, CLIENT_SECRET);
        String refreshToken = tokenBody.get("refresh_token").asText();
        String firstAccessToken = tokenBody.get("access_token").asText();

        String form = "grant_type=refresh_token&refresh_token=" + urlEncode(refreshToken)
                + "&client_id=" + urlEncode(CLIENT_ID) + "&client_secret=" + urlEncode(CLIENT_SECRET);
        HttpResponse<String> resp = post(url("/oauth2/token"), "application/x-www-form-urlencoded", form, null);
        assertEquals(200, resp.statusCode(), resp.body());
        JsonNode refreshedBody = mapper.readTree(resp.body());
        assertNotNull(refreshedBody.get("access_token"));
        assertNotEquals(firstAccessToken, refreshedBody.get("access_token").asText());
    }

    // ---------- NFR-15/NFR-18: negative token-endpoint cases, never 500 ----------

    @Test
    void nfr15_tokenEndpoint_completelyInvalidCode_returns400InvalidGrantNot500() throws Exception {
        String form = "grant_type=authorization_code&code=this-code-was-never-issued"
                + "&redirect_uri=" + urlEncode(REDIRECT_URI)
                + "&client_id=" + urlEncode(CLIENT_ID) + "&client_secret=" + urlEncode(CLIENT_SECRET)
                + "&code_verifier=" + urlEncode("irrelevant-verifier-value-that-is-at-least-43-characters-long");
        HttpResponse<String> resp = post(url("/oauth2/token"), "application/x-www-form-urlencoded", form, null);
        assertEquals(400, resp.statusCode());
        assertEquals("invalid_grant", mapper.readTree(resp.body()).get("error").asText());
    }

    @Test
    void nfr15_tokenEndpoint_mismatchedRedirectUri_returns400InvalidGrant() throws Exception {
        registerUser("mismatchredirect", "MismatchPassw0rd!");
        String verifier = "mismatch-redirect-verifier-must-be-at-least-43-characters-long";
        String code = fullLoginAndGetCode("mismatchredirect", "MismatchPassw0rd!", verifier, "mr-state");

        String form = "grant_type=authorization_code&code=" + urlEncode(code)
                + "&redirect_uri=" + urlEncode("http://127.0.0.1:9999/different-callback")
                + "&client_id=" + urlEncode(CLIENT_ID) + "&client_secret=" + urlEncode(CLIENT_SECRET)
                + "&code_verifier=" + urlEncode(verifier);
        HttpResponse<String> resp = post(url("/oauth2/token"), "application/x-www-form-urlencoded", form, null);
        assertEquals(400, resp.statusCode());
        assertEquals("invalid_grant", mapper.readTree(resp.body()).get("error").asText());
    }

    @Test
    void nfr15nfr18_tokenEndpoint_missingCodeVerifier_returns400NotHttp500() throws Exception {
        registerUser("missingverifier", "MissingVerifierPw1!");
        String verifier = "missing-verifier-test-value-must-be-at-least-43-characters-lo";
        String code = fullLoginAndGetCode("missingverifier", "MissingVerifierPw1!", verifier, "mv-state");

        String form = "grant_type=authorization_code&code=" + urlEncode(code)
                + "&redirect_uri=" + urlEncode(REDIRECT_URI)
                + "&client_id=" + urlEncode(CLIENT_ID) + "&client_secret=" + urlEncode(CLIENT_SECRET);
        HttpResponse<String> resp = post(url("/oauth2/token"), "application/x-www-form-urlencoded", form, null);
        assertEquals(400, resp.statusCode(), resp.body());
        assertNotNull(mapper.readTree(resp.body()).get("error"));
    }

    @Test
    void nfr18_tokenEndpoint_wrongCodeVerifier_returns400InvalidGrant() throws Exception {
        registerUser("wrongverifier", "WrongVerifierPw1!");
        String verifier = "wrong-verifier-test-correct-value-must-be-at-least-43-chars!!";
        String code = fullLoginAndGetCode("wrongverifier", "WrongVerifierPw1!", verifier, "wv-state");

        String form = "grant_type=authorization_code&code=" + urlEncode(code)
                + "&redirect_uri=" + urlEncode(REDIRECT_URI)
                + "&client_id=" + urlEncode(CLIENT_ID) + "&client_secret=" + urlEncode(CLIENT_SECRET)
                + "&code_verifier=" + urlEncode("this-does-not-hash-to-the-challenge-1234567890ABCDEFGHIJK");
        HttpResponse<String> resp = post(url("/oauth2/token"), "application/x-www-form-urlencoded", form, null);
        assertEquals(400, resp.statusCode());
        assertEquals("invalid_grant", mapper.readTree(resp.body()).get("error").asText());
    }

    @Test
    void nfr18_authorizationCode_singleUse_replayIsRejected() throws Exception {
        registerUser("replayuser", "ReplayUserPw1!");
        String verifier = "replay-test-verifier-value-must-be-at-least-43-characters-lo";
        String code = fullLoginAndGetCode("replayuser", "ReplayUserPw1!", verifier, "replay-state");

        JsonNode firstUse = exchangeCode(code, verifier, REDIRECT_URI, CLIENT_SECRET);
        assertNotNull(firstUse.get("access_token"), "first use of the code must succeed");

        String form = "grant_type=authorization_code&code=" + urlEncode(code)
                + "&redirect_uri=" + urlEncode(REDIRECT_URI)
                + "&client_id=" + urlEncode(CLIENT_ID) + "&client_secret=" + urlEncode(CLIENT_SECRET)
                + "&code_verifier=" + urlEncode(verifier);
        HttpResponse<String> replay = post(url("/oauth2/token"), "application/x-www-form-urlencoded", form, null);
        assertEquals(400, replay.statusCode(), "a second use of the same authorization code must be rejected");
        assertEquals("invalid_grant", mapper.readTree(replay.body()).get("error").asText());
    }

    @Test
    void nfr18_authorize_codeChallengeMethodPlain_rejectedBeforeCodeIssued() throws Exception {
        String verifier = "plain-method-test-verifier-must-be-at-least-43-characters-lo";
        String authorizeUrl = url("/oauth2/authorize") + "?response_type=code&client_id=" + CLIENT_ID
                + "&redirect_uri=" + urlEncode(REDIRECT_URI) + "&code_challenge=" + urlEncode(verifier)
                + "&code_challenge_method=plain&state=plain-state&scope=hello.read";

        HttpResponse<String> resp = client.send(
                HttpRequest.newBuilder(URI.create(authorizeUrl)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(400, resp.statusCode(), "code_challenge_method=plain must be rejected outright (NFR-18)");
        JsonNode body = mapper.readTree(resp.body());
        assertEquals("invalid_request", body.get("error").asText());
    }

    @Test
    void nfr18_authorize_codeChallengeMethodPlainCaseInsensitive_alsoRejected() throws Exception {
        String authorizeUrl = url("/oauth2/authorize") + "?response_type=code&client_id=" + CLIENT_ID
                + "&redirect_uri=" + urlEncode(REDIRECT_URI) + "&code_challenge=abc"
                + "&code_challenge_method=PLAIN&state=s&scope=hello.read";
        HttpResponse<String> resp = client.send(
                HttpRequest.newBuilder(URI.create(authorizeUrl)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(400, resp.statusCode());
    }

    // ---------- Helpers ----------

    private void registerUser(String username, String password) throws Exception {
        String body = mapper.writeValueAsString(Map.of("username", username, "password", password));
        // Distinct X-Forwarded-For per registration (trust-x-forwarded-for=true
        // above) purely to keep this suite's tests independent of NFR-5's real
        // 5/60s register rate limit - see class Javadoc.
        String syntheticIp = "10.77." + forwardedForCounter.incrementAndGet() + ".1";
        HttpRequest req = HttpRequest.newBuilder(URI.create(url("/api/v1/auth/register")))
                .header("Content-Type", "application/json")
                .header("X-Forwarded-For", syntheticIp)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(201, resp.statusCode(), resp.body());
    }

    private String authorizeUrl(String challenge, String state) {
        return url("/oauth2/authorize") + "?response_type=code&client_id=" + CLIENT_ID
                + "&redirect_uri=" + urlEncode(REDIRECT_URI) + "&code_challenge=" + urlEncode(challenge)
                + "&code_challenge_method=S256&state=" + urlEncode(state) + "&scope=hello.read";
    }

    /** Full authorize->login->code chain; returns null if not redirected with a code. */
    private String fullLoginAndGetCode(String username, String password, String verifier, String state)
            throws Exception {
        String challenge = base64UrlSha256(verifier);
        HttpResponse<Void> initial = client.send(
                HttpRequest.newBuilder(URI.create(authorizeUrl(challenge, state))).GET().build(),
                HttpResponse.BodyHandlers.discarding());
        String sessionCookie = extractSessionCookie(initial);
        assertNotNull(sessionCookie, "expected a session cookie from /oauth2/authorize");

        HttpResponse<String> loginPage = client.send(
                HttpRequest.newBuilder(URI.create(url("/login"))).header("Cookie", sessionCookie).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        String csrf = extractCsrfToken(loginPage.body());
        assertNotNull(csrf);

        String loginForm = "username=" + urlEncode(username) + "&password=" + urlEncode(password)
                + "&_csrf=" + urlEncode(csrf);
        HttpResponse<Void> loginResult = client.send(
                HttpRequest.newBuilder(URI.create(url("/login")))
                        .header("Cookie", sessionCookie)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(loginForm))
                        .build(),
                HttpResponse.BodyHandlers.discarding());
        assertEquals(302, loginResult.statusCode(), "valid credentials must redirect, not re-render (NFR-14)");
        String continueLocation = loginResult.headers().firstValue("Location").orElseThrow();
        String postLoginCookie = extractSessionCookie(loginResult);
        String activeCookie = postLoginCookie != null ? postLoginCookie : sessionCookie;

        HttpResponse<Void> continued = client.send(
                HttpRequest.newBuilder(URI.create(continueLocation)).header("Cookie", activeCookie).GET().build(),
                HttpResponse.BodyHandlers.discarding());
        assertEquals(302, continued.statusCode());
        String callbackLocation = continued.headers().firstValue("Location").orElseThrow();
        assertTrue(callbackLocation.startsWith(REDIRECT_URI));
        assertTrue(callbackLocation.contains("state=" + state));
        return extractQueryParam(callbackLocation, "code");
    }

    /** Performs /oauth2/authorize -> /login with bad credentials and returns the re-rendered HTML body. */
    private String attemptLoginDirectly(String username, String password) throws Exception {
        String verifier = "direct-login-attempt-verifier-must-be-at-least-43-characters!";
        String challenge = base64UrlSha256(verifier);
        HttpResponse<Void> initial = client.send(
                HttpRequest.newBuilder(URI.create(authorizeUrl(challenge, "direct-state"))).GET().build(),
                HttpResponse.BodyHandlers.discarding());
        String sessionCookie = extractSessionCookie(initial);

        HttpResponse<String> loginPage = client.send(
                HttpRequest.newBuilder(URI.create(url("/login"))).header("Cookie", sessionCookie).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        String csrf = extractCsrfToken(loginPage.body());

        String loginForm = "username=" + urlEncode(username) + "&password=" + urlEncode(password)
                + "&_csrf=" + urlEncode(csrf);
        HttpResponse<String> loginResult = client.send(
                HttpRequest.newBuilder(URI.create(url("/login")))
                        .header("Cookie", sessionCookie)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(loginForm))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, loginResult.statusCode(), "invalid credentials must re-render, not redirect (NFR-14)");
        assertNull(loginResult.headers().firstValue("Location").orElse(null));
        return loginResult.body();
    }

    private static String extractErrorText(String html) {
        Matcher m = Pattern.compile("role=\"alert\"[^>]*>(.*?)</p>").matcher(html);
        return m.find() ? m.group(1) : html;
    }

    private JsonNode exchangeCode(String code, String verifier, String redirectUri, String clientSecret)
            throws Exception {
        String form = "grant_type=authorization_code&code=" + urlEncode(code)
                + "&redirect_uri=" + urlEncode(redirectUri)
                + "&client_id=" + urlEncode(CLIENT_ID) + "&client_secret=" + urlEncode(clientSecret)
                + "&code_verifier=" + urlEncode(verifier);
        HttpResponse<String> resp = post(url("/oauth2/token"), "application/x-www-form-urlencoded", form, null);
        assertEquals(200, resp.statusCode(), resp.body());
        return mapper.readTree(resp.body());
    }

    private HttpResponse<String> get(String url, String cookie) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url)).GET();
        if (cookie != null) {
            b.header("Cookie", cookie);
        }
        return client.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> post(String url, String contentType, String body, String cookie) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", contentType)
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (cookie != null) {
            b.header("Cookie", cookie);
        }
        return client.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static boolean jsonArrayContains(JsonNode arrayNode, String value) {
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
        return audNode.isArray() ? jsonArrayContains(audNode, value) : value.equals(audNode.asText());
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
