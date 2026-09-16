package com.apitest;

import com.apitest.filter.RateLimitFilter;
import com.apitest.store.UserStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Re-verification (round 2), NFR-5: the fix for Bug 2 (spoofable
 * X-Forwarded-For rate-limit bypass) added an explicit opt-in flag,
 * {@code app.rate-limit.trust-x-forwarded-for}, for deployments that really
 * do sit behind a trusted reverse proxy which itself sets/overwrites that
 * header. That flag defaults to {@code false} (covered by
 * QaVerificationTest, run with the default test properties) - this class
 * covers the *opposite*, explicitly-opted-in path in its own Spring context
 * so it doesn't interfere with the default-path assertions, and confirms:
 * <ul>
 *   <li>when explicitly trusted, distinct X-Forwarded-For values legitimately
 *       get independent buckets (the documented, intended behavior for a real
 *       reverse-proxy deployment - this is NOT a bypass finding, since the
 *       operator has explicitly asserted they control that header upstream);</li>
 *   <li>a comma-separated X-Forwarded-For list is keyed on the first entry
 *       (the original client, per standard reverse-proxy convention), not the
 *       full raw header value nor a later hop.</li>
 * </ul>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "app.jwt-secret-key=qa-suite-secret-key-at-least-32-characters-long-xyz",
        "app.app-env=development",
        "app.rate-limit.trust-x-forwarded-for=true"
})
class QaTrustedProxyRateLimitTest {

    @LocalServerPort
    private int port;

    @Autowired
    private UserStore userStore;

    @Autowired
    private FilterRegistrationBean<RateLimitFilter> rateLimitFilterRegistration;

    private final ObjectMapper mapper = new ObjectMapper();
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    @BeforeEach
    void resetState() {
        userStore.clear();
        rateLimitFilterRegistration.getFilter().clear();
    }

    private HttpResponse<String> loginWithXff(String xff) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/v1/auth/login"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        mapper.writeValueAsString(Map.of("username", "trustedproxyuser", "password", "wrongpassword"))));
        if (xff != null) {
            b.header("X-Forwarded-For", xff);
        }
        return client.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void nfr5_whenExplicitlyTrusted_distinctXffValuesGetIndependentBuckets() throws Exception {
        // Exhaust the 10/60s login bucket for one spoofed IP...
        for (int i = 0; i < 10; i++) {
            HttpResponse<String> resp = loginWithXff("10.20.20.1");
            assertEquals(401, resp.statusCode(), "attempt " + i + " should not yet be throttled: " + resp.body());
        }
        assertEquals(429, loginWithXff("10.20.20.1").statusCode(),
                "11th attempt from the same trusted-proxy-reported IP should be throttled");

        // ...a different reported IP must still have its own, fresh bucket.
        assertEquals(401, loginWithXff("10.20.20.2").statusCode(),
                "a different X-Forwarded-For value must get an independent bucket when explicitly trusted");
    }

    @Test
    void nfr5_whenExplicitlyTrusted_commaSeparatedXffKeysOnFirstEntry() throws Exception {
        for (int i = 0; i < 10; i++) {
            HttpResponse<String> resp = loginWithXff("10.40.1.1, 10.40.1." + (2 + i));
            assertEquals(401, resp.statusCode(), "attempt " + i + " should not yet be throttled: " + resp.body());
        }
        // Only the trailing (proxy-appended) hops vary here; the first entry
        // (the original client, per convention) is unchanged, so this must
        // still hit the same, now-exhausted bucket.
        assertEquals(429, loginWithXff("10.40.1.1, 99.99.99.99").statusCode(),
                "must key on the first X-Forwarded-For entry, not the full raw header value");
    }

    @Test
    void nfr5_whenExplicitlyTrusted_noXffHeaderFallsBackToRemoteAddr() throws Exception {
        // Even with the flag on, a request with no X-Forwarded-For at all must
        // not bypass rate limiting entirely - it should fall back to the real
        // remote address bucket.
        boolean everThrottled = false;
        for (int i = 0; i < 15; i++) {
            if (loginWithXff(null).statusCode() == 429) {
                everThrottled = true;
                break;
            }
        }
        assertTrue(everThrottled, "requests with no X-Forwarded-For header must still be rate-limited via remoteAddr");
    }
}
