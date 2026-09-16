package com.apitest.config;

import jakarta.annotation.PostConstruct;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Centralized, environment-driven configuration (NFR-2).
 * <p>
 * Bound from {@code application.yml}, which in turn reads the real process
 * environment (or a {@code .env} file pre-loaded into system properties by
 * {@link com.apitest.ApiApplication} — see that class for details): same
 * env var names as the pre-Spring-Boot implementation (JWT_SECRET_KEY,
 * ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS, APP_ENV,
 * CORS_ALLOWED_ORIGINS).
 * <p>
 * {@link #validate()} preserves the old "fail fast at startup if
 * JWT_SECRET_KEY is missing or under 32 characters" behavior: it runs as a
 * {@code @PostConstruct} hook, so a bad/missing secret aborts Spring Boot
 * startup with a clear error rather than silently running insecurely.
 */
@Component
@ConfigurationProperties(prefix = "app")
public class AppProperties {

    private String jwtSecretKey = "";
    private int accessTokenExpireMinutes = 15;
    private int refreshTokenExpireDays = 7;
    private String appEnv = "development";
    private String corsAllowedOrigins = "http://localhost:3000";

    @PostConstruct
    public void validate() {
        if (jwtSecretKey == null || jwtSecretKey.isBlank()) {
            throw new IllegalStateException(
                    "JWT_SECRET_KEY is required (set it in the environment or .env)");
        }
        if (jwtSecretKey.length() < 32) {
            throw new IllegalStateException("JWT_SECRET_KEY must be at least 32 characters long");
        }
    }

    public List<String> corsOriginsList() {
        return Arrays.stream(corsAllowedOrigins.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());
    }

    public String getJwtSecretKey() {
        return jwtSecretKey;
    }

    public void setJwtSecretKey(String jwtSecretKey) {
        this.jwtSecretKey = jwtSecretKey;
    }

    public int getAccessTokenExpireMinutes() {
        return accessTokenExpireMinutes;
    }

    public void setAccessTokenExpireMinutes(int accessTokenExpireMinutes) {
        this.accessTokenExpireMinutes = accessTokenExpireMinutes;
    }

    public int getRefreshTokenExpireDays() {
        return refreshTokenExpireDays;
    }

    public void setRefreshTokenExpireDays(int refreshTokenExpireDays) {
        this.refreshTokenExpireDays = refreshTokenExpireDays;
    }

    public String getAppEnv() {
        return appEnv;
    }

    public void setAppEnv(String appEnv) {
        this.appEnv = appEnv;
    }

    public String getCorsAllowedOrigins() {
        return corsAllowedOrigins;
    }

    public void setCorsAllowedOrigins(String corsAllowedOrigins) {
        this.corsAllowedOrigins = corsAllowedOrigins;
    }
}
