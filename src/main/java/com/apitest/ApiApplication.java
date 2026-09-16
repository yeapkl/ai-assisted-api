package com.apitest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/**
 * Authenticated Hello World API — Spring Boot 3.x / Java 21.
 * <p>
 * Run (dev):     mvn spring-boot:run
 * Run (packaged): mvn package && java -jar target/hello-world-api.jar
 */
// We never use Spring Security's form-login/HTTP-Basic authentication (auth
// is our own JWT bearer check — see filter.JwtAuthFilter), so the default
// in-memory UserDetailsService autoconfiguration is irrelevant here; excluding
// it also avoids Spring Boot logging a random "generated security password"
// on every startup for a user that nothing in this app ever checks.
@SpringBootApplication(exclude = UserDetailsServiceAutoConfiguration.class)
public class ApiApplication {

    public static void main(String[] args) {
        loadDotEnvIntoSystemProperties();
        SpringApplication.run(ApiApplication.class, args);
    }

    /**
     * Optional {@code .env} file support, kept for parity with the previous
     * implementation's {@code Config.loadDotEnv} so local development still
     * works with "cp .env.example .env" and no exported shell variables.
     * <p>
     * This is plain config-file loading, not one of the security-critical or
     * cross-cutting primitives NFR-11 requires a library for (JSON, JWT,
     * password hashing, rate limiting, validation) — Spring Boot's
     * externalized configuration (env vars / application.yml) remains the
     * actual configuration mechanism (NFR-2); this only pre-seeds JVM system
     * properties from a local file before Spring's environment is built, and
     * real process environment variables always take precedence over it.
     */
    private static void loadDotEnvIntoSystemProperties() {
        Path path = Path.of(".env");
        if (!Files.exists(path)) {
            return;
        }
        Map<String, String> realEnv = System.getenv();
        try {
            for (String line : Files.readAllLines(path)) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }
                int idx = trimmed.indexOf('=');
                if (idx < 0) {
                    continue;
                }
                String key = trimmed.substring(0, idx).trim();
                String value = trimmed.substring(idx + 1).trim();
                // Real environment variables always win over .env file values.
                if (!realEnv.containsKey(key) && System.getProperty(key) == null) {
                    System.setProperty(key, value);
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read .env file", e);
        }
    }
}
