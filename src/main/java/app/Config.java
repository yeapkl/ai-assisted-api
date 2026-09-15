package app;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Centralized, environment-driven configuration.
 * NFR-2: secrets never hardcoded — loaded from environment / .env only.
 */
public final class Config {

    public final String jwtSecretKey; // REQUIRED — no default, fails fast if missing
    public final int accessTokenExpireMinutes;
    public final int refreshTokenExpireDays;
    public final String appEnv;
    public final String corsAllowedOrigins;

    public Config(Map<String, String> values) {
        this.jwtSecretKey = require(values, "JWT_SECRET_KEY");
        if (jwtSecretKey.length() < 32) {
            throw new IllegalArgumentException("JWT_SECRET_KEY must be at least 32 characters long");
        }
        this.accessTokenExpireMinutes = parseIntOrDefault(values.get("ACCESS_TOKEN_EXPIRE_MINUTES"), 15);
        this.refreshTokenExpireDays = parseIntOrDefault(values.get("REFRESH_TOKEN_EXPIRE_DAYS"), 7);
        this.appEnv = values.getOrDefault("APP_ENV", "development");
        this.corsAllowedOrigins = values.getOrDefault("CORS_ALLOWED_ORIGINS", "http://localhost:3000");
    }

    public List<String> corsOriginsList() {
        return Arrays.stream(corsAllowedOrigins.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());
    }

    /** Loads config from a .env file (if present) overlaid with real process environment variables. */
    public static Config load() {
        Map<String, String> merged = new HashMap<>();
        merged.putAll(loadDotEnv(Path.of(".env")));
        merged.putAll(System.getenv());
        return new Config(merged);
    }

    private static Map<String, String> loadDotEnv(Path path) {
        Map<String, String> map = new HashMap<>();
        if (!Files.exists(path)) {
            return map;
        }
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
                map.put(trimmed.substring(0, idx).trim(), trimmed.substring(idx + 1).trim());
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read .env file", e);
        }
        return map;
    }

    private static String require(Map<String, String> values, String key) {
        String v = values.get(key);
        if (v == null || v.isBlank()) {
            throw new IllegalArgumentException(key + " is required (set it in the environment or .env)");
        }
        return v;
    }

    private static int parseIntOrDefault(String value, int defaultValue) {
        return value == null ? defaultValue : Integer.parseInt(value);
    }
}
