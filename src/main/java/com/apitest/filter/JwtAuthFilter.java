package com.apitest.filter;

import com.apitest.security.JwtService;
import com.apitest.store.UserStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

/**
 * Our own JWT bearer-token authentication check for the one protected
 * business endpoint, {@code GET /api/v1/hello} (FR-3) — intentionally a
 * plain servlet {@link OncePerRequestFilter} rather than a full Spring
 * Security authentication filter chain (see {@code SecurityConfig}), since
 * this demo has a single symmetric-secret issuer/verifier and no external
 * identity provider.
 * <p>
 * On success, stores the authenticated username as a request attribute for
 * the controller to read. On any failure (missing header, malformed/expired/
 * tampered token, wrong token type, unknown user) it writes the same generic
 * 401 body the previous implementation used and short-circuits the chain.
 */
public class JwtAuthFilter extends OncePerRequestFilter {

    public static final String AUTHENTICATED_USERNAME_ATTR = "authenticatedUsername";

    private final JwtService jwtService;
    private final UserStore userStore;
    private final ObjectMapper objectMapper;

    public JwtAuthFilter(JwtService jwtService, UserStore userStore, ObjectMapper objectMapper) {
        this.jwtService = jwtService;
        this.userStore = userStore;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            writeUnauthorized(response);
            return;
        }
        String token = authHeader.substring("Bearer ".length()).trim();

        JwtService.TokenPayload payload;
        try {
            payload = jwtService.decodeToken(token);
        } catch (JwtService.TokenException e) {
            writeUnauthorized(response);
            return;
        }

        if (!"access".equals(payload.type())) {
            writeUnauthorized(response);
            return;
        }

        UserStore.User user = payload.subject() != null ? userStore.get(payload.subject()) : null;
        if (user == null) {
            writeUnauthorized(response);
            return;
        }

        request.setAttribute(AUTHENTICATED_USERNAME_ATTR, user.username());
        chain.doFilter(request, response);
    }

    private void writeUnauthorized(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        objectMapper.writeValue(response.getOutputStream(), Map.of("error", "Could not validate credentials"));
    }

    /** Registers the filter for only the protected route, matching the old ApiServer routing. */
    @Configuration
    public static class Registration {

        @Bean
        public FilterRegistrationBean<JwtAuthFilter> jwtAuthFilterRegistration(
                JwtService jwtService, UserStore userStore, ObjectMapper objectMapper) {
            FilterRegistrationBean<JwtAuthFilter> registration =
                    new FilterRegistrationBean<>(new JwtAuthFilter(jwtService, userStore, objectMapper));
            registration.addUrlPatterns("/api/v1/hello");
            registration.setName("jwtAuthFilter");
            return registration;
        }
    }
}
