package com.apitest.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Rate limiting on {@code /api/v1/auth/*} (NFR-5), implemented with the
 * established token-bucket library Bucket4j (NFR-11) instead of the old
 * hand-rolled sliding-window {@code RateLimiter.java}. Limits, matching the
 * previous implementation exactly:
 * <ul>
 *   <li>{@code /api/v1/auth/register}: 5 requests / 60s per IP</li>
 *   <li>{@code /api/v1/auth/login}: 10 requests / 60s per IP</li>
 *   <li>{@code /api/v1/auth/refresh}: 20 requests / 60s per IP</li>
 * </ul>
 */
public class RateLimitFilter extends OncePerRequestFilter {

    private record Limit(String endpoint, int capacity, Duration window) {
    }

    private static final Limit[] LIMITS = {
            new Limit("/api/v1/auth/register", 5, Duration.ofSeconds(60)),
            new Limit("/api/v1/auth/login", 10, Duration.ofSeconds(60)),
            new Limit("/api/v1/auth/refresh", 20, Duration.ofSeconds(60)),
    };

    private final ObjectMapper objectMapper;
    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    public RateLimitFilter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Limit limit = matchLimit(request.getRequestURI());
        if (limit == null) {
            chain.doFilter(request, response);
            return;
        }

        String key = limit.endpoint() + ":" + clientIp(request);
        Bucket bucket = buckets.computeIfAbsent(key, k -> newBucket(limit));
        if (!bucket.tryConsume(1)) {
            response.setStatus(429);
            response.setContentType("application/json");
            objectMapper.writeValue(response.getOutputStream(),
                    Map.of("error", "Too many requests. Please try again later."));
            return;
        }
        chain.doFilter(request, response);
    }

    private Bucket newBucket(Limit limit) {
        Bandwidth bandwidth = Bandwidth.builder()
                .capacity(limit.capacity())
                .refillGreedy(limit.capacity(), limit.window())
                .build();
        return Bucket.builder().addLimit(bandwidth).build();
    }

    private Limit matchLimit(String uri) {
        for (Limit limit : LIMITS) {
            if (limit.endpoint().equals(uri)) {
                return limit;
            }
        }
        return null;
    }

    private String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded;
        }
        String remote = request.getRemoteAddr();
        return remote != null ? remote : "unknown";
    }

    /** Test-only: resets all buckets so tests don't interfere with each other's counters. */
    public void clear() {
        buckets.clear();
    }

    /**
     * Registers the filter for the auth endpoints only, matching the old
     * ApiServer routing. Deliberately a single bean of type
     * {@code FilterRegistrationBean} (not also a plain {@code @Bean
     * RateLimitFilter}) — Spring Boot auto-registers any plain
     * {@code Filter} bean globally for "/*", which would otherwise run this
     * filter a second time on every auth request and silently double-count
     * rate-limit consumption.
     */
    @Configuration
    public static class Registration {

        @Bean
        public FilterRegistrationBean<RateLimitFilter> rateLimitFilterRegistration(ObjectMapper objectMapper) {
            FilterRegistrationBean<RateLimitFilter> registration =
                    new FilterRegistrationBean<>(new RateLimitFilter(objectMapper));
            registration.addUrlPatterns("/api/v1/auth/*");
            registration.setName("rateLimitFilter");
            return registration;
        }
    }
}
