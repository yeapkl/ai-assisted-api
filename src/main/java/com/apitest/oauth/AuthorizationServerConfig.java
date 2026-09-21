package com.apitest.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

/**
 * OAuth 2.1 Authorization Server (NFR-13..NFR-20), additive to the existing
 * JSON API - see {@code docs/requirements/hello-world-api.md} §3 and the
 * Handoff (§6) integration traps this class exists to satisfy:
 * <ol>
 *   <li>Login authenticates against {@link UserStoreUserDetailsService}
 *       (bridging the existing {@code UserStore}/{@code PasswordEncoder}),
 *       not a second set of Spring-Security-managed users.</li>
 *   <li>Issued access tokens carry an explicit {@code aud} claim (RFC 8707)
 *       via {@link #jwtCustomizer}, since Spring Authorization Server does
 *       not add one by default.</li>
 * </ol>
 * Two new {@link SecurityFilterChain} beans are added at higher precedence
 * than the existing, unmodified {@code SecurityConfig.securityFilterChain}
 * (which has no {@code @Order} and therefore still matches "/**" last,
 * {@code permitAll()}, completely unaffected by this addition - NFR-12):
 * one scoped to the AS endpoints themselves, one scoped to just
 * {@code /login}.
 */
@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http, AuthorizationServerSettings authorizationServerSettings, ObjectMapper objectMapper)
            throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.exceptionHandling(exceptions -> exceptions.defaultAuthenticationEntryPointFor(
                new LoginUrlAuthenticationEntryPoint("/login"),
                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)));

        // NFR-18: reject `code_challenge_method=plain` before a code can be
        // issued. Anchored to a core, always-registered Spring Security
        // filter (rather than OAuth2AuthorizationEndpointFilter itself,
        // whose filter-order registration isn't established on this
        // HttpSecurity until OAuth2AuthorizationServerConfigurer.init() runs
        // during http.build(), too late to reference here) so it reliably
        // runs before request processing reaches the AS's own filters.
        http.addFilterBefore(
                new RejectPlainPkceFilter(authorizationServerSettings.getAuthorizationEndpoint(), objectMapper),
                SecurityContextHolderFilter.class);

        return http.build();
    }

    /**
     * Scoped to exactly {@code /login} - the existing, unmodified
     * {@code SecurityConfig.securityFilterChain} (no explicit order, so
     * evaluated last / matches everything else) still handles every other
     * route with its original {@code permitAll()} behavior (NFR-12).
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 1)
    public SecurityFilterChain loginSecurityFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/login")
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .formLogin(form -> form
                        .loginPage("/login")
                        .failureHandler(new LoginFailureHandler()));
        return http.build();
    }

    /**
     * The single pre-registered OAuth client for mcp-server (Dynamic Client
     * Registration explicitly out of scope - hello-world-api.md §4).
     * <p>
     * <b>Deviation, verified empirically against the actual library
     * behavior (see handoff notes):</b> this client is registered as
     * <i>confidential</i> ({@code client_secret_basic}/{@code _post}), not a
     * fully public/secret-less client, even though NFR-18's PKCE-mandatory
     * posture is exactly the profile OAuth 2.1 designed for public clients.
     * Spring Authorization Server 1.3.2's {@code OAuth2RefreshTokenGenerator}
     * unconditionally refuses to issue a refresh token for the
     * authorization_code grant to any client registered with
     * {@code ClientAuthenticationMethod.NONE} - there is no supported
     * configuration flag to opt out of this. Since NFR-16 (refresh_token
     * grant support) is a hard requirement and the requirements docs never
     * mandate a secret-less client specifically, this client keeps PKCE
     * mandatory (S256-only, NFR-18 unaffected - see {@code requireProofKey}
     * below) *and* requires a client secret: strictly additive protection,
     * not a weakened one.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(OAuthProperties oAuthProperties,
            PasswordEncoder passwordEncoder) {
        RegisteredClient.Builder clientBuilder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(oAuthProperties.getClientId())
                // OAuth2ClientAuthenticationConfigurer looks up the app's own
                // PasswordEncoder bean (see OAuth2ConfigurerUtils.getOptionalBean)
                // and, if present, wires it directly into
                // ClientSecretAuthenticationProvider *instead of* Spring AS's
                // default DelegatingPasswordEncoder - so the stored secret
                // here must be a plain BCrypt hash (no {id} prefix), matching
                // exactly what our BCryptPasswordEncoder bean (NFR-1) itself
                // produces/expects. Verified empirically: an {bcrypt}-prefixed
                // value fails with "Encoded password does not look like
                // BCrypt" against this bean's own .matches().
                .clientSecret(passwordEncoder.encode(oAuthProperties.getClientSecret()))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope("hello.read")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(true)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(oAuthProperties.getAccessTokenExpireMinutes()))
                        .refreshTokenTimeToLive(Duration.ofDays(oAuthProperties.getRefreshTokenExpireDays()))
                        .reuseRefreshTokens(true)
                        .build());
        oAuthProperties.redirectUriList().forEach(clientBuilder::redirectUri);

        return new InMemoryRegisteredClientRepository(clientBuilder.build());
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings(OAuthProperties oAuthProperties) {
        return AuthorizationServerSettings.builder()
                .issuer(oAuthProperties.getIssuer())
                .build();
    }

    /**
     * NFR-19 / Handoff trap #2: stamps the configured resource-server
     * audience(s) onto every issued access token. Without this, Spring
     * Authorization Server emits no {@code aud} claim at all, and
     * mcp-server's audience validator would have nothing to check.
     * <p>
     * <b>QA-flagged gap fix (2026-09-21):</b> stamps <i>two</i> audience
     * values, not one - {@link OAuthProperties#getResourceAudience()}
     * ({@code mcp-server}) <i>and</i> {@link OAuthProperties#getSelfAudience()}
     * ({@code hello-world-api}), unconditionally (deduping only if the two
     * happen to be configured identically). Traced the actual token flow
     * before making this call (see {@code HelloApiTools.getHelloGreeting()}
     * in {@code mcp-server}): the single registered client's access token
     * is used for <i>both</i> calling mcp-server's own tools <i>and</i>,
     * via that tool's call-through, this app's own {@code GET /api/v1/hello}
     * - the exact same token, not a second one. Per RFC 8707, {@code aud}
     * MAY legitimately list multiple resource servers a token is valid
     * for, so this is the correct fix (not a workaround): it lets
     * {@code JwkConfig}'s OAuth {@code JwtDecoder} audience validator
     * require {@code hello-world-api} specifically for this app's own
     * endpoint - see {@link OAuthProperties#getSelfAudience()}'s Javadoc
     * for why this is unconditional rather than folded into
     * {@code resourceAudience} as a second comma-separated value (in
     * short: so this fix can't regress depending on how
     * {@code resourceAudience} happens to be configured), including the
     * accepted trade-off that follows from that choice.
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer(OAuthProperties oAuthProperties) {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                List<String> audience = oAuthProperties.getResourceAudience().equals(oAuthProperties.getSelfAudience())
                        ? List.of(oAuthProperties.getResourceAudience())
                        : List.of(oAuthProperties.getResourceAudience(), oAuthProperties.getSelfAudience());
                context.getClaims().audience(audience);
            }
        };
    }
}
