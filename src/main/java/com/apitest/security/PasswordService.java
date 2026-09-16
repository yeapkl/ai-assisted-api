package com.apitest.security;

import jakarta.annotation.PostConstruct;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * Password hashing (FR-4, NFR-1), delegated entirely to Spring Security's
 * {@link PasswordEncoder} abstraction (NFR-11) — no hand-rolled PBKDF2/hashing
 * routine. See {@link com.apitest.config.SecurityConfig} for the
 * {@code BCryptPasswordEncoder} bean definition.
 * <p>
 * Also owns the fixed "dummy hash" used by the login flow (NFR-4): a
 * pentest finding on the previous implementation showed that skipping the
 * password-hash comparison entirely for an unknown username created a timing
 * side-channel that let an attacker enumerate valid usernames. To close it,
 * a bcrypt comparison against this fixed dummy hash always runs on the
 * unknown-username path, so login response timing is the same whether the
 * username is unknown or the password was simply wrong.
 */
@Component
public class PasswordService {

    private final PasswordEncoder passwordEncoder;
    private String dummyHash;

    public PasswordService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @PostConstruct
    void init() {
        // The "password" hashed here is random and never used to log in —
        // only its hash is used, purely to give the verify-path something
        // constant-shaped to compare against.
        this.dummyHash = passwordEncoder.encode(UUID.randomUUID().toString());
    }

    public String hash(String rawPassword) {
        return passwordEncoder.encode(rawPassword);
    }

    public boolean matches(String rawPassword, String hashedPassword) {
        return passwordEncoder.matches(rawPassword, hashedPassword);
    }

    /** Fixed dummy hash for the NFR-4 timing-safe unknown-username login path. */
    public String dummyHash() {
        return dummyHash;
    }
}
