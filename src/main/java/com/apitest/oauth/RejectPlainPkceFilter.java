package com.apitest.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

/**
 * NFR-18: PKCE {@code S256} only - {@code plain} must be rejected, even
 * though RFC 7636 (and Spring Authorization Server's default authorization
 * endpoint) otherwise permits it. Runs ahead of Spring Authorization
 * Server's own authorization-endpoint filter (see
 * {@code AuthorizationServerConfig}) and short-circuits with a standard
 * OAuth {@code invalid_request} error before a code can ever be issued
 * against a {@code plain} challenge - this is an input-validation guard on
 * top of the library's own PKCE verification (which still does the real
 * S256 challenge/verifier comparison at the token endpoint), not a
 * hand-rolled PKCE implementation.
 */
public class RejectPlainPkceFilter extends OncePerRequestFilter {

    private final String authorizationEndpointPath;
    private final ObjectMapper objectMapper;

    public RejectPlainPkceFilter(String authorizationEndpointPath, ObjectMapper objectMapper) {
        this.authorizationEndpointPath = authorizationEndpointPath;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (authorizationEndpointPath.equals(request.getRequestURI())) {
            String method = request.getParameter("code_challenge_method");
            if (method != null && method.equalsIgnoreCase("plain")) {
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                objectMapper.writeValue(response.getOutputStream(), Map.of(
                        "error", "invalid_request",
                        "error_description", "code_challenge_method must be S256; plain is not permitted"));
                return;
            }
        }
        chain.doFilter(request, response);
    }
}
