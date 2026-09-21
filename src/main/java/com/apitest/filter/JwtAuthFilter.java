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
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
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
 * <p>
 * <b>OAuth addition:</b> also accepts a valid access token issued by the new
 * OAuth 2.1 Authorization Server (see {@code com.apitest.oauth}) - required
 * for {@code mcp-server}'s {@code get_hello_greeting} tool (see
 * {@code docs/requirements/mcp-server.md} FR-5) to actually be able to call
 * this endpoint with the OAuth-issued token it holds, which is a
 * differently-signed (RS256 vs. this filter's original HS256 jjwt) token
 * family. The original jjwt token path (FR-1..FR-3, NFR-2, NFR-3) is tried
 * first and is completely unchanged (NFR-12) - the OAuth decoder is only
 * consulted as a fallback when the jjwt decode fails, so no existing
 * caller's tokens or this endpoint's behavior for them changes at all; this
 * only widens which additional credential this one endpoint will also
 * accept.
 */
public class JwtAuthFilter extends OncePerRequestFilter {

    public static final String AUTHENTICATED_USERNAME_ATTR = "authenticatedUsername";

    private final JwtService jwtService;
    private final UserStore userStore;
    private final ObjectMapper objectMapper;
    private final JwtDecoder oauthJwtDecoder;

    public JwtAuthFilter(JwtService jwtService, UserStore userStore, ObjectMapper objectMapper,
            JwtDecoder oauthJwtDecoder) {
        this.jwtService = jwtService;
        this.userStore = userStore;
        this.objectMapper = objectMapper;
        this.oauthJwtDecoder = oauthJwtDecoder;
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

        String username = resolveUsernameFromLegacyToken(token);
        if (username == null) {
            username = resolveUsernameFromOAuthToken(token);
        }
        if (username == null) {
            writeUnauthorized(response);
            return;
        }

        UserStore.User user = userStore.get(username);
        if (user == null) {
            writeUnauthorized(response);
            return;
        }

        request.setAttribute(AUTHENTICATED_USERNAME_ATTR, user.username());
        chain.doFilter(request, response);
    }

    /** The original, unchanged jjwt HS256 access-token path (NFR-12). */
    private String resolveUsernameFromLegacyToken(String token) {
        try {
            JwtService.TokenPayload payload = jwtService.decodeToken(token);
            if (!"access".equals(payload.type())) {
                return null;
            }
            return payload.subject();
        } catch (JwtService.TokenException e) {
            return null;
        }
    }

    /**
     * The new OAuth 2.1 Authorization Server's RS256 access-token path.
     * <p>
     * <b>QA-flagged gap fix (2026-09-21):</b> {@code oauthJwtDecoder}
     * (see {@code com.apitest.oauth.JwkConfig}) now also validates the
     * token's {@code aud} claim against this app's own resource identifier
     * ({@code app.oauth.self-audience}, mirroring mcp-server's
     * {@code AudienceValidator}) - a validly-signed, unexpired token
     * audienced for some other, unrelated resource server is rejected by
     * {@code decode()} itself (thrown as {@code JwtValidationException}, a
     * {@link JwtException}), caught below exactly like any other decode
     * failure. No change was needed in this method itself.
     */
    private String resolveUsernameFromOAuthToken(String token) {
        try {
            Jwt jwt = oauthJwtDecoder.decode(token);
            return jwt.getSubject();
        } catch (JwtException e) {
            return null;
        }
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
                JwtService jwtService, UserStore userStore, ObjectMapper objectMapper, JwtDecoder oauthJwtDecoder) {
            FilterRegistrationBean<JwtAuthFilter> registration = new FilterRegistrationBean<>(
                    new JwtAuthFilter(jwtService, userStore, objectMapper, oauthJwtDecoder));
            registration.addUrlPatterns("/api/v1/hello");
            registration.setName("jwtAuthFilter");
            return registration;
        }
    }
}
