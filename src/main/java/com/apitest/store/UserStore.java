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

    public User create(String username, String hashedPassword) {
        User user = new User(username, hashedPassword);
        users.put(username, user);
        return user;
    }

    /** Test-only: clears all users between test cases. Never called from production code paths. */
    public void clear() {
        users.clear();
    }
}
