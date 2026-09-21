package com.apitest;

import com.apitest.oauth.OAuthProperties;
import com.apitest.store.UserStore;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.boot.test.context.TestConfiguration;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Independently verifies the developer's stated justification (see
 * {@code AuthorizationServerConfig.registeredClientRepository} Javadoc) for
 * why {@code mcp-server}'s registered OAuth client is confidential
 * (client_secret + mandatory PKCE) rather than a fully public,
 * secret-less client, which is a real deviation from the OAuth 2.1
 * public-client-with-PKCE profile NFR-18 assumes.
 * <p>
 * This test overrides the app's {@code RegisteredClientRepository} bean
 * (test-only, via {@code @Primary} in a {@code @TestConfiguration} - no
 * production code is modified) to register the <b>same</b> client as a
 * genuinely public client ({@link ClientAuthenticationMethod#NONE}, no
 * secret, PKCE still mandatory) and drives a full authorization_code+PKCE
 * round trip against it with no client authentication at all, to see
 * empirically what Spring Authorization Server 1.3.2 actually does for the
 * refresh_token grant in that configuration - rather than trusting the
 * developer's comment.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "app.jwt-secret-key=qa-public-client-suite-secret-key-at-least-32-chars",
        "app.oauth.signing-key-secret=qa-public-client-suite-signing-key-at-least-32c",
        // Still required (fails fast if blank/short) even though this test's
        // overridden client doesn't use it - the confidential default client
        // bean is still constructed by the untouched production config.
        "app.oauth.client-secret=qa-public-client-suite-unused-client-secret-32char",
        "app.oauth.redirect-uris=http://127.0.0.1:8765/callback"
})
class QaOAuthPublicClientRefreshTokenTest {

    private static final String CLIENT_ID = "mcp-server";
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

    @TestConfiguration
    static class PublicClientOverrideConfig {
        @Bean
        @Primary
        public RegisteredClientRepository publicRegisteredClientRepository(
                OAuthProperties props, PasswordEncoder passwordEncoder) {
            RegisteredClient publicClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId(CLIENT_ID)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri(REDIRECT_URI)
                    .scope("hello.read")
                    .clientSettings(ClientSettings.builder()
                            .requireAuthorizationConsent(false)
                            .requireProofKey(true)
                            .build())
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenTimeToLive(Duration.ofMinutes(props.getAccessTokenExpireMinutes()))
                            .refreshTokenTimeToLive(Duration.ofDays(props.getRefreshTokenExpireDays()))
                            .build())
                    .build();
            return new InMemoryRegisteredClientRepository(publicClient);
        }
    }

    @BeforeEach
    void resetState() {
        userStore.clear();
    }

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    @Test
    void publicClientAuthorizationCodeGrant_verifyWhetherRefreshTokenIsActuallyIssued() throws Exception {
        registerUser("publicclientuser", "PublicClientPw1!");
        String verifier = "public-client-test-verifier-value-must-be-at-least-43-chars!";
        String code = fullLoginAndGetCode("publicclientuser", "PublicClientPw1!", verifier, "public-state");
        assertNotNull(code, "public client + PKCE must still be able to complete the browser login and obtain a code");

        // No client_secret, no Basic auth header - exactly what a real public client sends.
        String form = "grant_type=authorization_code&code=" + urlEncode(code)
                + "&redirect_uri=" + urlEncode(REDIRECT_URI)
                + "&client_id=" + urlEncode(CLIENT_ID)
                + "&code_verifier=" + urlEncode(verifier);
        HttpResponse<String> tokenResp = client.send(
                HttpRequest.newBuilder(URI.create(url("/oauth2/token")))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(form))
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        // Deliberately no hard assertion on status/shape here beyond "not a
        // 500" - the whole point of this test is to observe and record what
        // Spring Authorization Server 1.3.2 actually does, per the QA
        // instruction to verify the developer's claim empirically. See
        // docs/qa/hello-world-api-report.md for the recorded outcome.
        System.out.println("QA FINDING (public client + authorization_code grant): token endpoint returned HTTP "
                + tokenResp.statusCode() + " body=" + tokenResp.body());

        if (tokenResp.statusCode() == 200) {
            JsonNode body = mapper.readTree(tokenResp.body());
            boolean hasRefreshToken = body.has("refresh_token") && !body.get("refresh_token").isNull();
            System.out.println("QA FINDING: public client authorization_code grant succeeded; refresh_token "
                    + (hasRefreshToken ? "WAS issued (contradicts developer's stated reason for using a "
                            + "confidential client)" : "was NOT issued (confirms developer's stated reason)"));
        } else {
            System.out.println("QA FINDING: public client authorization_code grant itself failed with status "
                    + tokenResp.statusCode() + " - see body above for the exact OAuth error returned.");
        }
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
