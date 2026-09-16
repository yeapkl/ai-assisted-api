package com.apitest;

import com.apitest.filter.RateLimitFilter;
import com.apitest.security.JwtService;
import com.apitest.store.UserStore;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Independent QA verification suite for the Spring Boot "Authenticated Hello
 * World" API, covering FR-1..FR-7 and NFR-1..NFR-11 from
 * docs/requirements/hello-world-api.md, including negative/edge cases beyond
 * the developer's own sanity suite (ApiIntegrationTest). Written independently
 * of the developer's ApiIntegrationTest; does not reuse or depend on it.
 * <p>
 * Run: mvn test -Dtest=QaVerificationTest,QaProductionHeadersTest,QaTokenExpiryTest,QaSecretFailFastTest
 * (or simply `mvn test` to run this alongside the rest of the suite).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "app.jwt-secret-key=qa-suite-secret-key-at-least-32-characters-long-xyz",
        "app.app-env=development",
        "app.cors-allowed-origins=http://localhost:3000"
})
class QaVerificationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private UserStore userStore;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private FilterRegistrationBean<RateLimitFilter> rateLimitFilterRegistration;

    private final ObjectMapper mapper = new ObjectMapper();
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    @BeforeEach
    void resetState() {
        userStore.clear();
        rateLimitFilterRegistration.getFilter().clear();
    }

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    private HttpResponse<String> rawPost(String path, String contentType, String body) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url(path)))
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        if (contentType != null) {
            b.header("Content-Type", contentType);
        }
        return client.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> postJson(String path, Object body) throws Exception {
        return rawPost(path, "application/json", mapper.writeValueAsString(body));
    }

    private HttpResponse<String> get(String path, String authHeader) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url(path))).GET();
        if (authHeader != null) {
            b.header("Authorization", authHeader);
        }
        return client.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> method(String httpMethod, String path, String authHeader) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url(path)))
                .method(httpMethod, HttpRequest.BodyPublishers.noBody());
        if (authHeader != null) {
            b.header("Authorization", authHeader);
        }
        return client.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> options(String path, String origin, String reqMethod) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url(path)))
                .method("OPTIONS", HttpRequest.BodyPublishers.noBody())
                .header("Origin", origin)
                .header("Access-Control-Request-Method", reqMethod);
        return client.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> register(String username, String password) throws Exception {
        return postJson("/api/v1/auth/register", Map.of("username", username, "password", password));
    }

    private HttpResponse<String> login(String username, String password) throws Exception {
        return postJson("/api/v1/auth/login", Map.of("username", username, "password", password));
    }

    private String accessTokenFor(String user, String pass) throws Exception {
        register(user, pass);
        HttpResponse<String> loginResp = login(user, pass);
        return mapper.readTree(loginResp.body()).get("access_token").asText();
    }

    /** Decodes JWT claims without verifying the signature, purely to inspect iat/exp/sub/type. */
    private JsonNode decodeClaimsUnverified(String jwt) throws Exception {
        String[] parts = jwt.split("\\.");
        byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
        return mapper.readTree(payload);
    }

    // ---------------------------------------------------------------
    // FR-7: GET /health unauthenticated
    // ---------------------------------------------------------------

    @Test
    void fr7_health_isUnauthenticatedAndOk() throws Exception {
        HttpResponse<String> resp = get("/health", null);
        assertEquals(200, resp.statusCode());
        assertEquals(Map.of("status", "ok"), mapper.readValue(resp.body(), Map.class));
    }

    @Test
    void fr7_health_wrongMethodReturns405NotCrash() throws Exception {
        HttpResponse<String> resp = method("DELETE", "/health", null);
        assertEquals(405, resp.statusCode());
    }

    // ---------------------------------------------------------------
    // FR-4 / NFR-1 / NFR-7: registration
    // ---------------------------------------------------------------

    @Test
    void fr4_register_createsUserReturns201() throws Exception {
        HttpResponse<String> resp = register("alice", "GoodPassw0rd!");
        assertEquals(201, resp.statusCode());
    }

    @Test
    void nfr1_register_passwordStoredAsBcryptHashNotPlaintext() throws Exception {
        register("hashcheck", "PlaintextPassw0rd!");
        UserStore.User user = userStore.get("hashcheck");
        assertNotNull(user);
        assertNotEquals("PlaintextPassw0rd!", user.hashedPassword());
        assertTrue(user.hashedPassword().matches("^\\$2[aby]?\\$.*"),
                "expected a bcrypt hash ($2a/$2b/$2y$...), got: " + user.hashedPassword());
    }

    @Test
    void nfr1_register_samePasswordProducesDifferentHashesEachTime() throws Exception {
        register("saltcheck1", "SamePassw0rd!");
        register("saltcheck2", "SamePassw0rd!");
        String h1 = userStore.get("saltcheck1").hashedPassword();
        String h2 = userStore.get("saltcheck2").hashedPassword();
        assertNotEquals(h1, h2, "identical passwords must not produce identical hashes (salted hashing)");
    }

    @Test
    void fr4_register_duplicateUsernameRejectedWith400GenericBody() throws Exception {
        assertEquals(201, register("dup1", "GoodPassw0rd!").statusCode());
        HttpResponse<String> resp = register("dup1", "DifferentPassw0rd!");
        assertEquals(400, resp.statusCode());
        assertFalse(resp.body().toLowerCase().contains("exist"),
                "duplicate-registration error should not confirm the username already exists: " + resp.body());
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2})
    void nfr7_register_usernameTooShortRejectedWith422(int len) throws Exception {
        String username = "a".repeat(len);
        HttpResponse<String> resp = register(username, "GoodPassw0rd!");
        assertEquals(422, resp.statusCode());
    }

    @Test
    void nfr7_register_usernameBoundaryLengthsAccepted() throws Exception {
        assertEquals(201, register("a".repeat(3), "GoodPassw0rd!").statusCode(), "3-char username (min) should be accepted");
        assertEquals(201, register("b".repeat(32), "GoodPassw0rd!").statusCode(), "32-char username (max) should be accepted");
    }

    @Test
    void nfr7_register_usernameOverMaxLengthRejectedWith422() throws Exception {
        assertEquals(422, register("c".repeat(33), "GoodPassw0rd!").statusCode());
    }

    @Test
    void nfr7_register_passwordUnderMinLengthRejectedWith422() throws Exception {
        assertEquals(422, register("pwshort", "a".repeat(7)).statusCode());
    }

    @Test
    void nfr7_register_passwordBoundaryLengthsAccepted() throws Exception {
        assertEquals(201, register("pwmin", "a".repeat(8)).statusCode(), "8-char password (min) should be accepted");
        assertEquals(201, register("pwmax", "a".repeat(128)).statusCode(), "128-char password (max) should be accepted");
    }

    @Test
    void nfr7_register_passwordOverMaxLengthRejectedWith422() throws Exception {
        assertEquals(422, register("pwtoolong", "a".repeat(129)).statusCode());
    }

    @Test
    void nfr7_register_oversizedPasswordPayloadHandledGracefully() throws Exception {
        // 2 MB password: must not crash the server or hang; should be a clean 422.
        HttpResponse<String> resp = register("oversized1", "a".repeat(2_000_000));
        assertEquals(422, resp.statusCode());
    }

    @ParameterizedTest
    @ValueSource(strings = {"bad name!", "admin'--", "<script>alert(1)</script>", "user;drop table", "user\ttab"})
    void nfr7_register_invalidUsernameCharactersRejectedWith422(String badUsername) throws Exception {
        HttpResponse<String> resp = register(badUsername, "GoodPassw0rd!");
        assertEquals(422, resp.statusCode(), "username '" + badUsername + "' should be rejected");
    }

    @Test
    void nfr7_register_malformedJsonRejectedWith422() throws Exception {
        HttpResponse<String> resp = rawPost("/api/v1/auth/register", "application/json", "not-json-at-all");
        assertEquals(422, resp.statusCode());
    }

    @Test
    void nfr7_register_emptyBodyRejectedWith422() throws Exception {
        HttpResponse<String> resp = rawPost("/api/v1/auth/register", "application/json", "");
        assertEquals(422, resp.statusCode());
    }

    @Test
    void nfr7_register_emptyJsonObjectRejectedWith422() throws Exception {
        HttpResponse<String> resp = rawPost("/api/v1/auth/register", "application/json", "{}");
        assertEquals(422, resp.statusCode());
    }

    @Test
    void nfr7_register_wrongJsonTypeForUsernameRejectedNotCrash() throws Exception {
        HttpResponse<String> resp = rawPost("/api/v1/auth/register", "application/json",
                "{\"username\":12345,\"password\":\"GoodPassw0rd!\"}");
        // Wrong JSON type is a client input error either way: accept 422 (validation-shaped)
        // but must NOT be a 500 (that would indicate the malformed-type case isn't handled as
        // a client error at all).
        assertNotEquals(500, resp.statusCode(),
                "wrong JSON type for a field must not surface as a 500 Internal Server Error: " + resp.body());
    }

    @Test
    void nfr7_register_extraUnknownFieldsIgnored() throws Exception {
        HttpResponse<String> resp = rawPost("/api/v1/auth/register", "application/json",
                "{\"username\":\"extraf1\",\"password\":\"GoodPassw0rd!\",\"isAdmin\":true}");
        assertEquals(201, resp.statusCode(), "unknown extra fields should be ignored, not rejected");
    }

    @Test
    void fr4_register_wrongHttpMethodReturns405() throws Exception {
        assertEquals(405, method("GET", "/api/v1/auth/register", null).statusCode());
    }

    // ---------------------------------------------------------------
    // Concurrency / conflicting-state edge case (FR-4)
    // ---------------------------------------------------------------

    @Test
    void fr4_register_concurrentDuplicateRegistrationsOnlyOneShouldSucceed() throws Exception {
        int attempts = 5; // matches the register bucket capacity (5/60s) so all attempts pass the rate limiter
        ExecutorService pool = Executors.newFixedThreadPool(attempts);
        CountDownLatch ready = new CountDownLatch(attempts);
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger created = new AtomicInteger(0);
        AtomicInteger rejected = new AtomicInteger(0);
        try {
            List<java.util.concurrent.Future<?>> futures = new java.util.ArrayList<>();
            for (int i = 0; i < attempts; i++) {
                final int idx = i;
                futures.add(pool.submit(() -> {
                    try {
                        ready.countDown();
                        go.await();
                        HttpResponse<String> resp = register("racer_concurrent", "Password" + idx + "!AAA");
                        if (resp.statusCode() == 201) {
                            created.incrementAndGet();
                        } else if (resp.statusCode() == 400) {
                            rejected.incrementAndGet();
                        }
                    } catch (Exception ignored) {
                    }
                }));
            }
            ready.await(5, TimeUnit.SECONDS);
            go.countDown();
            for (java.util.concurrent.Future<?> f : futures) {
                f.get(10, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }
        assertEquals(1, created.get(),
                "exactly one concurrent registration of the same username should succeed with 201; got " + created.get()
                        + " successes and " + rejected.get() + " rejections out of " + attempts + " concurrent attempts"
                        + " (FR-4: creates *a* user -- duplicate/racing registrations for the same username must not"
                        + " both succeed, silently overwriting the earlier user's password hash)");
    }

    // ---------------------------------------------------------------
    // FR-1 / FR-5 / NFR-4: login
    // ---------------------------------------------------------------

    @Test
    void fr1fr5_login_validCredentialsReturnsAccessAndRefreshTokens() throws Exception {
        register("bob", "GoodPassw0rd!");
        HttpResponse<String> resp = login("bob", "GoodPassw0rd!");
        assertEquals(200, resp.statusCode());
        JsonNode body = mapper.readTree(resp.body());
        assertNotNull(body.get("access_token").asText());
        assertNotNull(body.get("refresh_token").asText());
        assertEquals("bearer", body.get("token_type").asText());
    }

    @Test
    void nfr4_login_wrongPasswordReturns401() throws Exception {
        register("carol", "GoodPassw0rd!");
        assertEquals(401, login("carol", "wrongpassword").statusCode());
    }

    @Test
    void nfr4_login_unknownUserAndWrongPasswordReturnByteIdenticalResponses() throws Exception {
        register("carol2", "GoodPassw0rd!");
        HttpResponse<String> wrongPw = login("carol2", "wrongpassword");
        HttpResponse<String> unknownUser = login("does-not-exist-xyz", "whatever123");
        assertEquals(wrongPw.statusCode(), unknownUser.statusCode());
        assertEquals(wrongPw.body(), unknownUser.body());
        assertEquals(401, wrongPw.statusCode());
    }

    @Test
    void nfr4_login_timingSoftCheck_unknownUserNotDramaticallyFasterThanWrongPassword() throws Exception {
        // Best-effort timing check only (NFR-4). Not a precise cryptographic timing-attack
        // proof (that requires many more samples and a controlled environment), but flags a
        // gross regression, e.g. if the dummy-hash comparison were ever skipped again.
        register("timinguser", "GoodPassw0rd!");
        int iterations = 15;
        long wrongPwTotalNanos = 0;
        long unknownUserTotalNanos = 0;
        for (int i = 0; i < iterations; i++) {
            long t0 = System.nanoTime();
            login("timinguser", "wrongpassword" + i);
            wrongPwTotalNanos += System.nanoTime() - t0;

            long t1 = System.nanoTime();
            login("no-such-user-" + i, "whatever" + i);
            unknownUserTotalNanos += System.nanoTime() - t1;
        }
        double wrongPwAvgMs = wrongPwTotalNanos / iterations / 1_000_000.0;
        double unknownUserAvgMs = unknownUserTotalNanos / iterations / 1_000_000.0;
        double ratio = Math.max(wrongPwAvgMs, unknownUserAvgMs) / Math.min(wrongPwAvgMs, unknownUserAvgMs);
        assertTrue(ratio < 3.0,
                "unknown-user vs wrong-password average login latency differs too much to be timing-safe: "
                        + "wrongPwAvgMs=" + wrongPwAvgMs + " unknownUserAvgMs=" + unknownUserAvgMs + " ratio=" + ratio);
    }

    @Test
    void nfr7_login_missingFieldsRejectedWith422() throws Exception {
        HttpResponse<String> resp = rawPost("/api/v1/auth/login", "application/json", "{\"username\":\"onlyusername\"}");
        assertEquals(422, resp.statusCode());
    }

    @Test
    void nfr7_login_malformedJsonRejectedWith422() throws Exception {
        assertEquals(422, rawPost("/api/v1/auth/login", "application/json", "{not valid json").statusCode());
    }

    @Test
    void fr5_login_wrongHttpMethodReturns405() throws Exception {
        assertEquals(405, method("GET", "/api/v1/auth/login", null).statusCode());
    }

    // ---------------------------------------------------------------
    // FR-3: protected /api/v1/hello
    // ---------------------------------------------------------------

    @Test
    void fr3_hello_validAccessTokenReturnsMessageAndServerTime() throws Exception {
        String token = accessTokenFor("dave", "GoodPassw0rd!");
        HttpResponse<String> resp = get("/api/v1/hello", "Bearer " + token);
        assertEquals(200, resp.statusCode());
        JsonNode body = mapper.readTree(resp.body());
        assertEquals("Hello, dave!", body.get("message").asText());
        Instant serverTime = Instant.parse(body.get("server_time_utc").asText());
        assertTrue(Math.abs(Duration.between(serverTime, Instant.now()).toSeconds()) < 10);
    }

    @Test
    void fr3_hello_noAuthorizationHeaderReturns401() throws Exception {
        assertEquals(401, get("/api/v1/hello", null).statusCode());
    }

    @Test
    void fr3_hello_nonBearerSchemeReturns401() throws Exception {
        assertEquals(401, get("/api/v1/hello", "Token abc123").statusCode());
    }

    @Test
    void fr3_hello_lowercaseBearerSchemeReturns401() throws Exception {
        String token = accessTokenFor("caseuser", "GoodPassw0rd!");
        // RFC 6750 scheme is case-insensitive in principle, but confirming this
        // implementation's exact (case-sensitive "Bearer ") behavior either way --
        // it must not silently authenticate with a header it doesn't recognize.
        assertEquals(401, get("/api/v1/hello", "bearer " + token).statusCode());
    }

    @Test
    void fr3_hello_emptyBearerTokenReturns401() throws Exception {
        assertEquals(401, get("/api/v1/hello", "Bearer ").statusCode());
    }

    @Test
    void fr3_hello_tamperedTokenSignatureReturns401() throws Exception {
        String token = accessTokenFor("eve", "GoodPassw0rd!");
        assertEquals(401, get("/api/v1/hello", "Bearer " + token + "tamperedsuffix").statusCode());
    }

    @Test
    void fr3_hello_tamperedTokenPayloadReturns401() throws Exception {
        String token = accessTokenFor("eve2", "GoodPassw0rd!");
        String[] parts = token.split("\\.");
        String forgedPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"sub\":\"someone-else\",\"type\":\"access\"}".getBytes(StandardCharsets.UTF_8));
        String forgedToken = parts[0] + "." + forgedPayload + "." + parts[2];
        assertEquals(401, get("/api/v1/hello", "Bearer " + forgedToken).statusCode());
    }

    @Test
    void fr3_hello_algNoneTokenRejected() throws Exception {
        String token = accessTokenFor("algnoneuser", "GoodPassw0rd!");
        String[] parts = token.split("\\.");
        String noneHeader = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String forged = noneHeader + "." + parts[1] + ".";
        assertEquals(401, get("/api/v1/hello", "Bearer " + forged).statusCode());
    }

    @Test
    void fr3_hello_malformedTokenGarbageStringReturns401() throws Exception {
        assertEquals(401, get("/api/v1/hello", "Bearer not.a.jwt").statusCode());
    }

    @Test
    void fr2fr3_hello_refreshTokenCannotAccessProtectedRoute() throws Exception {
        register("frank", "GoodPassw0rd!");
        HttpResponse<String> loginResp = login("frank", "GoodPassw0rd!");
        String refreshToken = mapper.readTree(loginResp.body()).get("refresh_token").asText();
        assertEquals(401, get("/api/v1/hello", "Bearer " + refreshToken).statusCode());
    }

    @Test
    void fr3_hello_tokenWithUnknownTypeClaimRejected() throws Exception {
        // Bypasses the DTO/controller layer entirely to prove JwtAuthFilter itself enforces
        // type == "access", not merely "not refresh".
        register("typecheckuser", "GoodPassw0rd!");
        String weirdToken = jwtService.createToken("typecheckuser", "id_token");
        assertEquals(401, get("/api/v1/hello", "Bearer " + weirdToken).statusCode());
    }

    @Test
    void fr3_hello_validTokenForDeletedOrUnknownUserRejected() throws Exception {
        // A structurally valid, correctly-signed access token whose subject no longer
        // exists in the user store (e.g. would-be deleted account) must not authenticate.
        String ghostToken = jwtService.createToken("ghost-user-never-registered", "access");
        assertEquals(401, get("/api/v1/hello", "Bearer " + ghostToken).statusCode());
    }

    @Test
    void fr3_hello_wrongHttpMethodWithValidTokenReturns405() throws Exception {
        String token = accessTokenFor("methoduser", "GoodPassw0rd!");
        HttpResponse<String> resp = method("POST", "/api/v1/hello", "Bearer " + token);
        assertEquals(405, resp.statusCode());
    }

    // ---------------------------------------------------------------
    // FR-2 / FR-6: refresh
    // ---------------------------------------------------------------

    @Test
    void fr6_refresh_validRefreshTokenReturnsNewAccessToken() throws Exception {
        register("gina", "GoodPassw0rd!");
        HttpResponse<String> loginResp = login("gina", "GoodPassw0rd!");
        String refreshToken = mapper.readTree(loginResp.body()).get("refresh_token").asText();
        HttpResponse<String> resp = postJson("/api/v1/auth/refresh", Map.of("refresh_token", refreshToken));
        assertEquals(200, resp.statusCode());
        assertNotNull(mapper.readTree(resp.body()).get("access_token"));
    }

    @Test
    void fr6_refresh_accessTokenCannotBeUsedAsRefreshToken() throws Exception {
        register("henry", "GoodPassw0rd!");
        HttpResponse<String> loginResp = login("henry", "GoodPassw0rd!");
        String accessToken = mapper.readTree(loginResp.body()).get("access_token").asText();
        HttpResponse<String> resp = postJson("/api/v1/auth/refresh", Map.of("refresh_token", accessToken));
        assertEquals(401, resp.statusCode());
    }

    @Test
    void fr6_refresh_tamperedTokenReturns401() throws Exception {
        register("ian", "GoodPassw0rd!");
        HttpResponse<String> loginResp = login("ian", "GoodPassw0rd!");
        String refreshToken = mapper.readTree(loginResp.body()).get("refresh_token").asText();
        HttpResponse<String> resp = postJson("/api/v1/auth/refresh", Map.of("refresh_token", refreshToken + "x"));
        assertEquals(401, resp.statusCode());
    }

    @Test
    void fr6_refresh_missingFieldRejectedWith422() throws Exception {
        assertEquals(422, rawPost("/api/v1/auth/refresh", "application/json", "{}").statusCode());
    }

    @Test
    void fr6_refresh_malformedJsonRejectedWith422() throws Exception {
        assertEquals(422, rawPost("/api/v1/auth/refresh", "application/json", "{{{").statusCode());
    }

    @Test
    void fr6_refresh_tokenForDeletedUserRejected() throws Exception {
        register("jill", "GoodPassw0rd!");
        HttpResponse<String> loginResp = login("jill", "GoodPassw0rd!");
        String refreshToken = mapper.readTree(loginResp.body()).get("refresh_token").asText();
        userStore.clear(); // simulate the account being removed
        HttpResponse<String> resp = postJson("/api/v1/auth/refresh", Map.of("refresh_token", refreshToken));
        assertEquals(401, resp.statusCode());
    }

    @Test
    void fr6_refresh_wrongHttpMethodReturns405() throws Exception {
        assertEquals(405, method("GET", "/api/v1/auth/refresh", null).statusCode());
    }

    // ---------------------------------------------------------------
    // NFR-3: token lifetimes
    // ---------------------------------------------------------------

    @Test
    void nfr3_accessTokenExpiryIs15Minutes() throws Exception {
        register("ttluser", "GoodPassw0rd!");
        HttpResponse<String> loginResp = login("ttluser", "GoodPassw0rd!");
        String accessToken = mapper.readTree(loginResp.body()).get("access_token").asText();
        JsonNode claims = decodeClaimsUnverified(accessToken);
        assertEquals("access", claims.get("type").asText());
        long ttlSeconds = claims.get("exp").asLong() - claims.get("iat").asLong();
        assertEquals(15 * 60L, ttlSeconds, "access token TTL must be exactly 15 minutes");
    }

    @Test
    void nfr3_refreshTokenExpiryIs7Days() throws Exception {
        register("ttluser2", "GoodPassw0rd!");
        HttpResponse<String> loginResp = login("ttluser2", "GoodPassw0rd!");
        String refreshToken = mapper.readTree(loginResp.body()).get("refresh_token").asText();
        JsonNode claims = decodeClaimsUnverified(refreshToken);
        assertEquals("refresh", claims.get("type").asText());
        long ttlSeconds = claims.get("exp").asLong() - claims.get("iat").asLong();
        assertEquals(7 * 24 * 3600L, ttlSeconds, "refresh token TTL must be exactly 7 days");
    }

    // ---------------------------------------------------------------
    // NFR-6: security headers (including on error responses)
    // ---------------------------------------------------------------

    private void assertBaselineSecurityHeaders(HttpResponse<String> resp) {
        assertEquals("nosniff", resp.headers().firstValue("X-Content-Type-Options").orElse(null));
        assertEquals("DENY", resp.headers().firstValue("X-Frame-Options").orElse(null));
        assertEquals("no-store", resp.headers().firstValue("Cache-Control").orElse(null));
    }

    @Test
    void nfr6_securityHeadersPresentOnSuccessResponse() throws Exception {
        assertBaselineSecurityHeaders(get("/health", null));
    }

    @Test
    void nfr6_securityHeadersPresentOn401Response() throws Exception {
        assertBaselineSecurityHeaders(get("/api/v1/hello", null));
    }

    @Test
    void nfr6_securityHeadersPresentOn422Response() throws Exception {
        assertBaselineSecurityHeaders(register("x", "short"));
    }

    @Test
    void nfr6_securityHeadersPresentOn429Response() throws Exception {
        for (int i = 0; i < 5; i++) {
            register("ratelim" + i, "GoodPassw0rd!");
        }
        HttpResponse<String> resp = register("ratelim-over", "GoodPassw0rd!");
        assertEquals(429, resp.statusCode());
        assertBaselineSecurityHeaders(resp);
    }

    @Test
    void nfr6_hstsAbsentInDevelopmentEnv() throws Exception {
        HttpResponse<String> resp = get("/health", null);
        assertTrue(resp.headers().firstValue("Strict-Transport-Security").isEmpty(),
                "HSTS should not be advertised over a non-TLS dev deployment");
    }

    // ---------------------------------------------------------------
    // NFR-8: CORS
    // ---------------------------------------------------------------

    @Test
    void nfr8_cors_allowedOriginReflectedExactly() throws Exception {
        HttpResponse<String> resp = get("/health", null); // baseline
        HttpRequest req = HttpRequest.newBuilder(URI.create(url("/health")))
                .header("Origin", "http://localhost:3000").GET().build();
        HttpResponse<String> corsResp = client.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, corsResp.statusCode());
        assertEquals("http://localhost:3000", corsResp.headers().firstValue("Access-Control-Allow-Origin").orElse(null));
        assertNotEquals("*", corsResp.headers().firstValue("Access-Control-Allow-Origin").orElse(null));
    }

    @Test
    void nfr8_cors_disallowedOriginGetsNoAllowOriginHeaderAndIsRejected() throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url("/health")))
                .header("Origin", "http://evil.example.com").GET().build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        assertTrue(resp.headers().firstValue("Access-Control-Allow-Origin").isEmpty(),
                "disallowed origin must not receive an Access-Control-Allow-Origin header");
        assertEquals(403, resp.statusCode());
    }

    @Test
    void nfr8_cors_preflightForAllowedOriginSucceeds() throws Exception {
        HttpResponse<String> resp = options("/api/v1/auth/login", "http://localhost:3000", "POST");
        assertEquals(200, resp.statusCode());
        assertEquals("http://localhost:3000", resp.headers().firstValue("Access-Control-Allow-Origin").orElse(null));
    }

    @Test
    void nfr8_cors_preflightForDisallowedOriginRejected() throws Exception {
        HttpResponse<String> resp = options("/api/v1/auth/login", "http://evil.example.com", "POST");
        assertEquals(403, resp.statusCode());
        assertTrue(resp.headers().firstValue("Access-Control-Allow-Origin").isEmpty());
    }

    // ---------------------------------------------------------------
    // NFR-5: rate limiting (Bucket4j, per-IP per-endpoint)
    // ---------------------------------------------------------------

    @Test
    void nfr5_rateLimit_registerBlockedAfter5PerMinute() throws Exception {
        for (int i = 0; i < 5; i++) {
            assertEquals(201, register("burst" + i, "GoodPassw0rd!").statusCode());
        }
        assertEquals(429, register("burst5", "GoodPassw0rd!").statusCode());
    }

    @Test
    void nfr5_rateLimit_loginBlockedAfter10PerMinute() throws Exception {
        register("loginlimit", "GoodPassw0rd!");
        for (int i = 0; i < 10; i++) {
            login("loginlimit", "wrongpassword");
        }
        assertEquals(429, login("loginlimit", "wrongpassword").statusCode());
    }

    @Test
    void nfr5_rateLimit_refreshBlockedAfter20PerMinute() throws Exception {
        register("refreshlimit", "GoodPassw0rd!");
        HttpResponse<String> loginResp = login("refreshlimit", "GoodPassw0rd!");
        String refreshToken = mapper.readTree(loginResp.body()).get("refresh_token").asText();
        for (int i = 0; i < 20; i++) {
            postJson("/api/v1/auth/refresh", Map.of("refresh_token", refreshToken));
        }
        HttpResponse<String> resp = postJson("/api/v1/auth/refresh", Map.of("refresh_token", refreshToken));
        assertEquals(429, resp.statusCode());
    }

    @Test
    void nfr5_rateLimit_bucketsArePerEndpointNotShared() throws Exception {
        // Register (and log in once) *before* exhausting the register bucket, so the
        // later login attempt only exercises the login bucket, not the register bucket.
        register("loginstillworks", "GoodPassw0rd!");
        for (int i = 0; i < 5; i++) {
            register("perendpoint" + i, "GoodPassw0rd!");
        }
        assertEquals(429, register("perendpoint_over", "GoodPassw0rd!").statusCode());
        // Login bucket must be unaffected by register bucket exhaustion.
        assertEquals(200, login("loginstillworks", "GoodPassw0rd!").statusCode());
    }

    @Test
    void nfr5_rateLimit_consumedEvenByRequestsThatFailValidation() throws Exception {
        // Confirmed developer behavior: the bucket is consumed even for requests that
        // are later rejected by Bean Validation (422). 5 invalid attempts should still
        // exhaust the register bucket, so a 6th, *valid* request is throttled (429), not 201.
        for (int i = 0; i < 5; i++) {
            assertEquals(422, register("bad name " + i, "short").statusCode());
        }
        HttpResponse<String> resp = register("validaftershort", "GoodPassw0rd!");
        assertEquals(429, resp.statusCode());
    }

    @Test
    void nfr5_rateLimit_bypassableViaSpoofedXForwardedFor_shouldNotBe() throws Exception {
        // NFR-5 exists "to reduce brute-force risk". If a client can defeat the per-IP
        // bucket simply by sending a different X-Forwarded-For value on every request,
        // rate limiting provides no real protection against brute force from a single
        // attacker machine hitting the server directly (no trusted reverse proxy in front
        // of this deployment establishes X-Forwarded-For authoritatively).
        register("xffuser", "GoodPassw0rd!");
        boolean everThrottled = false;
        for (int i = 0; i < 15; i++) {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url("/api/v1/auth/login")))
                    .header("Content-Type", "application/json")
                    .header("X-Forwarded-For", "10.1.2." + i)
                    .POST(HttpRequest.BodyPublishers.ofString(
                            mapper.writeValueAsString(Map.of("username", "xffuser", "password", "wrongpassword"))))
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 429) {
                everThrottled = true;
                break;
            }
        }
        assertTrue(everThrottled,
                "rate limiting must not be trivially bypassable by spoofing a different X-Forwarded-For "
                        + "value per request; login limit (10/60s) should still trigger 429 within 15 attempts "
                        + "from what is really a single client, but it never did (NFR-5 defeated)");
    }

    // ---------------------------------------------------------------
    // NFR-9: no sensitive data leaked in error/response bodies
    // ---------------------------------------------------------------

    @Test
    void nfr9_registerResponseNeverEchoesRawPassword() throws Exception {
        String rawPassword = "SuperSecretPassw0rd!";
        HttpResponse<String> resp = register("noleaks", rawPassword);
        assertFalse(resp.body().contains(rawPassword));
    }

    @Test
    void nfr9_unexpectedErrorBodyContainsNoStackTraceOrExceptionClassName() throws Exception {
        // Trigger the generic exception handler path (unsupported Content-Type).
        HttpResponse<String> resp = rawPost("/api/v1/auth/login", "text/plain", "hello");
        String body = resp.body();
        assertFalse(body.contains("Exception"), "error body must not leak exception class names: " + body);
        assertFalse(body.toLowerCase().contains("at com.apitest"), "error body must not leak a stack trace: " + body);
    }

    // ---------------------------------------------------------------
    // General robustness: unmapped routes / unsupported content types
    // must be handled as proper 4xx client errors, not surfaced as 500s
    // (Scope §1: "production-shaped REST API"; NFR-9 error-response hygiene).
    // ---------------------------------------------------------------

    @Test
    void general_unknownRouteReturns404NotInternalServerError() throws Exception {
        HttpResponse<String> resp = get("/api/v1/this-route-does-not-exist", null);
        assertNotEquals(500, resp.statusCode(),
                "an unmapped route must not return 500 Internal Server Error: " + resp.body());
        assertEquals(404, resp.statusCode());
    }

    @Test
    void general_unsupportedContentTypeReturnsClientErrorNot500() throws Exception {
        HttpResponse<String> resp = rawPost("/api/v1/auth/login", "text/plain", "hello");
        assertNotEquals(500, resp.statusCode(),
                "an unsupported Content-Type must be a 4xx client error, not 500 Internal Server Error: " + resp.body());
    }
}
