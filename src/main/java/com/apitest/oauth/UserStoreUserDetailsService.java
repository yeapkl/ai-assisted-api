package com.apitest.oauth;

import com.apitest.store.UserStore;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

/**
 * Bridges Spring Security's {@link UserDetailsService} abstraction (needed
 * by the OAuth 2.1 Authorization Server's {@code /login} form) to the
 * existing, already-reviewed {@link UserStore} - NFR-17 / Handoff trap #1
 * in hello-world-api.md §6: this must be the *same* backing store as
 * {@code /api/v1/auth/*}, not a second, independently-provisioned set of
 * Spring-Security-managed users (e.g. {@code InMemoryUserDetailsManager}).
 * <p>
 * The returned {@link UserDetails}' password is the bcrypt hash already
 * stored in {@link UserStore}, so the {@code PasswordEncoder} bean shared
 * with {@code /api/v1/auth/login} (see {@code SecurityConfig}) is what
 * actually performs the credential comparison - one password, one hash,
 * one encoder, two entry points.
 */
@Component
public class UserStoreUserDetailsService implements UserDetailsService {

    private final UserStore userStore;

    public UserStoreUserDetailsService(UserStore userStore) {
        this.userStore = userStore;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserStore.User user = userStore.get(username);
        if (user == null) {
            // Spring Security's DaoAuthenticationProvider (default
            // hideUserNotFoundExceptions=true) collapses this into the same
            // generic "Bad credentials" AuthenticationException it throws
            // for a wrong password, and performs its own dummy password
            // comparison on this path - so the OAuth login form gets the
            // same "no user-enumeration hint" property NFR-4 requires for
            // the JSON /api/v1/auth/login path, without duplicating that
            // logic here.
            throw new UsernameNotFoundException("User not found");
        }
        return User.withUsername(user.username())
                .password(user.hashedPassword())
                .authorities("ROLE_USER")
                .build();
    }
}
