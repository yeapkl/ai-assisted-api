package com.apitest.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
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
 * <p>
 * <b>QA-flagged gap fix (2026-09-21):</b> the OAuth 2.1 Authorization Server
 * addition (see {@code com.apitest.oauth}) introduced {@code /login},
 * {@code /oauth2/authorize}, and {@code /oauth2/token} with no throttling at
 * all - {@code /login} in particular is an unthrottled password-guessing
 * surface functionally equivalent to {@code /api/v1/auth/login}. Reusing
 * this exact same per-endpoint/per-IP Bucket4j pattern (not a different
 * rate-limiting approach - NFR-11) rather than hand-rolling a second one:
 * <ul>
 *   <li>{@code POST /login}: 10 requests / 60s per IP - the actual
 *       password-check request (Spring Security's {@code formLogin} filter
 *       authenticates on the {@code POST}, not the {@code GET} that merely
 *       renders the form/CSRF token), so at least as strict as
 *       {@code /api/v1/auth/login}. Scoped to {@code POST} only so fetching
 *       the login page itself (no credential involved) isn't throttled by
 *       the same, stricter, password-guessing-focused budget.</li>
 *   <li>{@code /oauth2/token}: 20 requests / 60s per IP - no password
 *       involved, but a {@code grant_type=authorization_code} request pairs a
 *       code with a {@code code_verifier}, so still bounded, matching
 *       {@code /api/v1/auth/refresh}'s existing limit.</li>
 *   <li>{@code /oauth2/authorize}: 30 requests / 60s per IP - more permissive
 *       (no credential/secret check happens here, it only issues a login
 *       form or a redirect), but still bounded rather than wide open.</li>
 * </ul>
 * Each limit is keyed by its own {@code endpoint} string (see {@code key} in
 * {@link #doFilterInternal}), so these new buckets are completely isolated
 * from the pre-existing {@code /api/v1/auth/*} ones - no shared/colliding
 * state between old and new endpoints, and no change to the pre-existing
 * limits' behavior (same map, same class, distinct keys).
 */
public class RateLimitFilter extends OncePerRequestFilter {

    /** {@code method == null} means "any HTTP method" (the original, unchanged behavior). */
    private record Limit(String endpoint, String method, int capacity, Duration window) {
    }

    private static final Limit[] LIMITS = {
            new Limit("/api/v1/auth/register", null, 5, Duration.ofSeconds(60)),
            new Limit("/api/v1/auth/login", null, 10, Duration.ofSeconds(60)),
            new Limit("/api/v1/auth/refresh", null, 20, Duration.ofSeconds(60)),
            new Limit("/login", "POST", 10, Duration.ofSeconds(60)),
            new Limit("/oauth2/token", null, 20, Duration.ofSeconds(60)),
            new Limit("/oauth2/authorize", null, 30, Duration.ofSeconds(60)),
    };

    private final ObjectMapper objectMapper;
    private final boolean trustXForwardedFor;
    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    public RateLimitFilter(ObjectMapper objectMapper) {
        this(objectMapper, false);
    }

    public RateLimitFilter(ObjectMapper objectMapper, boolean trustXForwardedFor) {
        this.objectMapper = objectMapper;
        this.trustXForwardedFor = trustXForwardedFor;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Limit limit = matchLimit(request.getRequestURI(), request.getMethod());
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

    private Limit matchLimit(String uri, String method) {
        for (Limit limit : LIMITS) {
            if (limit.endpoint().equals(uri) && (limit.method() == null || limit.method().equalsIgnoreCase(method))) {
                return limit;
            }
        }
        return null;
    }

    /**
     * NFR-5 bug fix: previously this unconditionally trusted the
     * client-supplied {@code X-Forwarded-For} header, which let any attacker
     * fully bypass rate limiting by sending a unique value per request. This
     * app has no documented reverse proxy in front of it by default (see
     * docs/requirements/hello-world-api.md, .env.example), so the safe
     * default is to key on the actual TCP peer address
     * ({@link HttpServletRequest#getRemoteAddr()}), which the client cannot
     * spoof. {@code X-Forwarded-For} is only honored when explicitly opted
     * into via {@code app.rate-limit.trust-x-forwarded-for=true} (off by
     * default) for real deployments that sit behind a trusted reverse proxy
     * that overwrites/sets that header itself.
     */
    private String clientIp(HttpServletRequest request) {
        if (trustXForwardedFor) {
            String forwarded = request.getHeader("X-Forwarded-For");
            if (forwarded != null && !forwarded.isBlank()) {
                // Standard convention: the first entry is the original client as seen by
                // the nearest trusted hop; take it, trimmed, ignoring any further entries.
                return forwarded.split(",")[0].trim();
            }
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
     * ApiServer routing. Deliberately {@code FilterRegistrationBean} beans
     * (not also a plain {@code @Bean RateLimitFilter}) — Spring Boot
     * auto-registers any plain {@code Filter} bean globally for "/*", which
     * would otherwise run this filter a second time on every request and
     * silently double-count rate-limit consumption.
     * <p>
     * <b>QA-flagged gap fix (2026-09-21):</b> registers the <i>same</i>
     * {@link RateLimitFilter} instance (one shared Bucket4j-backed bucket
     * map - see class Javadoc for why the per-endpoint keying already keeps
     * old/new buckets isolated) under <i>two</i> separate
     * {@code FilterRegistrationBean}s with deliberately different orders,
     * rather than one covering all patterns:
     * <ul>
     *   <li>{@code /api/v1/auth/*}: unchanged, default order (after Spring
     *       Security's own {@code HeaderWriterFilter}) - preserves the
     *       existing, already-tested behavior that a 429 here still carries
     *       the standard security headers (NFR-6).</li>
     *   <li>{@code /oauth2/*}, {@code /login}: {@code HIGHEST_PRECEDENCE} -
     *       these paths are guarded by {@code AuthorizationServerConfig}'s
     *       own {@code SecurityFilterChain}s, which perform the actual
     *       credential/secret check (formLogin's password check on
     *       {@code /login}, client-secret/PKCE checks on
     *       {@code /oauth2/token}) <i>inside</i> that same
     *       {@code FilterChainProxy} invocation - a rate limit applied
     *       afterward would be too late (the guess would already have been
     *       checked). Trade-off, accepted deliberately: a 429 on these
     *       specific paths therefore does not carry Spring Security's
     *       standard headers (added by a filter later in that same chain,
     *       never reached) - preventing the brute-force/guessing attempt
     *       itself outweighs that, and no NFR-6 test covers these new paths.
     * </ul>
     */
    @Configuration
    public static class Registration {

        @Bean
        public RateLimitFilter rateLimitFilter(
                ObjectMapper objectMapper,
                @Value("${app.rate-limit.trust-x-forwarded-for:false}") boolean trustXForwardedFor) {
            return new RateLimitFilter(objectMapper, trustXForwardedFor);
        }

        @Bean
        public FilterRegistrationBean<RateLimitFilter> rateLimitFilterRegistration(RateLimitFilter rateLimitFilter) {
            FilterRegistrationBean<RateLimitFilter> registration = new FilterRegistrationBean<>(rateLimitFilter);
            registration.addUrlPatterns("/api/v1/auth/*");
            registration.setName("rateLimitFilter");
            return registration;
        }

        @Bean
        public FilterRegistrationBean<RateLimitFilter> oauthRateLimitFilterRegistration(
                RateLimitFilter rateLimitFilter) {
            FilterRegistrationBean<RateLimitFilter> registration = new FilterRegistrationBean<>(rateLimitFilter);
            registration.addUrlPatterns("/oauth2/*", "/login");
            registration.setName("oauthRateLimitFilter");
            // Must run before Spring Security's own filter chain for these
            // paths (see class-level note above) - Spring Security's
            // FilterChainProxy registers at SecurityProperties.DEFAULT_FILTER_ORDER
            // (-100); HIGHEST_PRECEDENCE guarantees this always runs first.
            registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
            return registration;
        }
    }
}
