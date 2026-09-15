package app;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Demo in-memory user store.
 * NOTE (flagged in improvement plan): replace with a real database
 * (e.g. Postgres) before production use. Data does not persist across
 * restarts.
 */
public final class Store {

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

    public void clear() {
        users.clear();
    }
}
