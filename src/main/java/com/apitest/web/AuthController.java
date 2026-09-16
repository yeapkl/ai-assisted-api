package com.apitest.web;

import com.apitest.security.JwtService;
import com.apitest.security.PasswordService;
import com.apitest.store.UserStore;
import com.apitest.web.dto.LoginRequest;
import com.apitest.web.dto.RefreshRequest;
import com.apitest.web.dto.RegisterRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/** FR-1, FR-2, FR-4, FR-5, FR-6: registration, login, and token refresh. */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final UserStore userStore;
    private final PasswordService passwordService;
    private final JwtService jwtService;

    public AuthController(UserStore userStore, PasswordService passwordService, JwtService jwtService) {
        this.userStore = userStore;
        this.passwordService = passwordService;
        this.jwtService = jwtService;
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@Valid @RequestBody RegisterRequest request) {
        // FR-4: rely solely on UserStore.create's atomic putIfAbsent for the
        // conflict decision (no separate exists()-then-create()) so concurrent
        // duplicate registrations can't race past a check-then-act gap and
        // both succeed. Hashing happens before the atomic insert since it's
        // needed either way and doesn't affect the atomicity of the insert.
        UserStore.User created = userStore.create(request.username(), passwordService.hash(request.password()));
        if (created == null) {
            // NFR-4: generic message, doesn't confirm the username is taken.
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "Registration failed"));
        }
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("message", "User registered successfully"));
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@Valid @RequestBody LoginRequest request) {
        UserStore.User user = userStore.get(request.username());

        // Pentest finding: always run the password hash comparison, even for a
        // nonexistent user, against a fixed dummy hash. Skipping it when the
        // user is unknown created a timing side-channel that let an attacker
        // enumerate valid usernames despite the identical error message.
        String hashedToCheck = user != null ? user.hashedPassword() : passwordService.dummyHash();
        boolean passwordOk = passwordService.matches(request.password(), hashedToCheck);

        if (user == null || !passwordOk) {
            // NFR-4: identical error whether the username or the password was wrong.
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Invalid credentials"));
        }

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("access_token", jwtService.createToken(user.username(), "access"));
        resp.put("refresh_token", jwtService.createToken(user.username(), "refresh"));
        resp.put("token_type", "bearer");
        return ResponseEntity.ok(resp);
    }

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refresh(@Valid @RequestBody RefreshRequest request) {
        JwtService.TokenPayload payload;
        try {
            payload = jwtService.decodeToken(request.refreshToken());
        } catch (JwtService.TokenException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Invalid refresh token"));
        }

        if (!"refresh".equals(payload.type())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Invalid refresh token"));
        }

        String username = payload.subject();
        if (username == null || username.isBlank() || !userStore.exists(username)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Invalid refresh token"));
        }

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("access_token", jwtService.createToken(username, "access"));
        resp.put("token_type", "bearer");
        return ResponseEntity.ok(resp);
    }
}
