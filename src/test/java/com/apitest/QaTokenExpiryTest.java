package com.apitest;

import com.apitest.store.UserStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * NFR-3: verifies that an actually-expired access token is rejected end to
 * end (not just that the TTL claim is correct, which QaVerificationTest
 * checks separately). Uses a dedicated context with an artificially
 * negative access-token TTL so the token is already expired the instant
 * it's issued, without needing to sleep 15 real minutes.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "app.jwt-secret-key=qa-suite-secret-key-at-least-32-characters-long-xyz",
        "app.app-env=development",
        "app.access-token-expire-minutes=-1"
})
class QaTokenExpiryTest {

    @LocalServerPort
    private int port;

    @Autowired
    private UserStore userStore;

    private final ObjectMapper mapper = new ObjectMapper();
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    @Test
    void nfr3_expiredAccessTokenRejectedWith401() throws Exception {
        userStore.clear();
        HttpRequest registerReq = HttpRequest.newBuilder(URI.create(url("/api/v1/auth/register")))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        mapper.writeValueAsString(Map.of("username", "expireduser", "password", "GoodPassw0rd!"))))
                .build();
        client.send(registerReq, HttpResponse.BodyHandlers.ofString());

        HttpRequest loginReq = HttpRequest.newBuilder(URI.create(url("/api/v1/auth/login")))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        mapper.writeValueAsString(Map.of("username", "expireduser", "password", "GoodPassw0rd!"))))
                .build();
        HttpResponse<String> loginResp = client.send(loginReq, HttpResponse.BodyHandlers.ofString());
        String accessToken = mapper.readTree(loginResp.body()).get("access_token").asText();

        HttpRequest helloReq = HttpRequest.newBuilder(URI.create(url("/api/v1/hello")))
                .header("Authorization", "Bearer " + accessToken)
                .GET().build();
        HttpResponse<String> helloResp = client.send(helloReq, HttpResponse.BodyHandlers.ofString());
        assertEquals(401, helloResp.statusCode(), "already-expired access token must be rejected");
    }
}
