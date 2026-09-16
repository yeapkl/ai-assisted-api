package com.apitest;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * NFR-6: HSTS is only meaningful (and only added by SecurityConfig) when
 * app.app-env=production. Verified in a dedicated Spring context so it
 * doesn't interfere with QaVerificationTest's development-mode assertion
 * that HSTS is absent.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "app.jwt-secret-key=qa-suite-secret-key-at-least-32-characters-long-xyz",
        "app.app-env=production"
})
class QaProductionHeadersTest {

    @LocalServerPort
    private int port;

    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    @Test
    void nfr6_hstsPresentInProductionEnv() throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/health")).GET().build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, resp.statusCode());
        String hsts = resp.headers().firstValue("Strict-Transport-Security").orElse(null);
        assertTrue(hsts != null && hsts.contains("max-age="), "expected HSTS header in production, got: " + hsts);
    }
}
