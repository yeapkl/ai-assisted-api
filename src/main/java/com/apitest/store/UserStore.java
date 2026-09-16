package com.apitest.store;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Demo in-memory user store.
 * NOTE (flagged in improvement plan): replace with a real database
 * (e.g. Postgres) before production use. Data does not persist across
 * restarts.
 */
@Component
public class UserStore {

    public record User(String username, String hashedPassword) {
    }

    private final Map<String, User> users = new ConcurrentHashMap<>();

    public User get(String username) {
        if (username == null) {
            return null;
        }
        return users.get(username);
    }

    public boolean exists(String username) {
        return username != null && users.containsKey(username);
    }

    /**
     * Atomically creates a user iff the username isn't already taken.
     * Uses {@link ConcurrentHashMap#putIfAbsent} so the check-then-act of
     * "does this username exist" and "create it" happens as a single atomic
     * operation, closing a TOCTOU race where concurrent registrations of the
     * same username could otherwise all succeed and silently overwrite each
     * other's password hash (FR-4 bug).
     *
     * @return the newly created {@link User}, or {@code null} if the
     *         username was already taken (by a prior call or a concurrent
     *         racing call that won).
     */
    public User create(String username, String hashedPassword) {
        User user = new User(username, hashedPassword);
        User previous = users.putIfAbsent(username, user);
        return previous == null ? user : null;
    }

    /** Test-only: clears all users between test cases. Never called from production code paths. */
    public void clear() {
        users.clear();
    }
}
