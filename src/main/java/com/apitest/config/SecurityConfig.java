package com.apitest.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * Security-header (NFR-6) and CORS (NFR-8) configuration, via Spring
 * Security's standard mechanisms rather than hand-written response-header
 * code (the old {@code ApiServer.SecurityHeadersFilter}).
 * <p>
 * Note: we deliberately do NOT configure Spring Security's authentication
 * filter chain / form login here — authentication is our own JWT bearer
 * check (see {@link com.apitest.filter.JwtAuthFilter}), so every request is
 * {@code permitAll()} at the Spring Security layer; access control for
 * {@code /api/v1/hello} is enforced by {@code JwtAuthFilter} instead.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final AppProperties appProperties;

    public SecurityConfig(AppProperties appProperties) {
        this.appProperties = appProperties;
    }

    /** NFR-1: bcrypt password hashing via Spring Security's PasswordEncoder abstraction. */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Stateless bearer-token API: no server-side session, no cookies, so
                // CSRF protection (designed for cookie-based session auth) doesn't apply.
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .headers(headers -> {
                    headers
                            .contentTypeOptions(withDefaults -> {
                            }) // X-Content-Type-Options: nosniff
                            .frameOptions(frame -> frame.deny()) // X-Frame-Options: DENY
                            .cacheControl(cache -> cache.disable())
                            .addHeaderWriter(new StaticHeadersWriter("Cache-Control", "no-store"))
                            .referrerPolicy(referrer ->
                                    referrer.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER));
                    if ("production".equals(appProperties.getAppEnv())) {
                        headers.addHeaderWriter(new StaticHeadersWriter(
                                "Strict-Transport-Security", "max-age=63072000; includeSubDomains"));
                    }
                });

        return http.build();
    }

    /** NFR-8: explicit CORS allow-list (never a wildcard) sourced from CORS_ALLOWED_ORIGINS. */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.copyOf(appProperties.corsOriginsList()));
        configuration.setAllowedMethods(List.of("GET", "POST"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        configuration.setAllowCredentials(false);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
