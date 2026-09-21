package com.apitest.mcp.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

/**
 * mcp-server's OAuth 2.1 resource-server posture (NFR-1..NFR-7). No
 * URL-based {@code authorizeHttpRequests} rule can distinguish between MCP
 * tools multiplexed behind the single {@code POST /mcp} endpoint (see
 * {@link McpToolAuthorizationFilter}), so this chain intentionally
 * {@code permitAll()}s at the HTTP layer and delegates real, per-tool
 * enforcement to that filter - registered here rather than left to Spring
 * Boot's default security auto-configuration (which would otherwise put a
 * generated-password HTTP Basic login in front of every endpoint).
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtDecoder jwtDecoder,
            OAuthResourceServerProperties properties) throws Exception {
        McpAuthenticationEntryPoint entryPoint =
                new McpAuthenticationEntryPoint(properties.protectedResourceMetadataUrl());

        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .addFilterBefore(new McpToolAuthorizationFilter(jwtDecoder, entryPoint), BasicAuthenticationFilter.class);

        return http.build();
    }
}
