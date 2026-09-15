package app;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Minimal in-process sliding-window rate limiter (NFR-5).
 * Good enough for a single-process demo; the improvement plan calls out
 * swapping this for a shared Redis-backed limiter in production (multi-instance
 * deployments each get their own counters otherwise).
 */
public final class RateLimiter {

    private final Map<String, Deque<Long>> hits = new ConcurrentHashMap<>();

    public boolean isAllowed(String key, int maxRequests, int windowSeconds) {
        long now = System.nanoTime();
        long windowNanos = windowSeconds * 1_000_000_000L;
        Deque<Long> q = hits.computeIfAbsent(key, k -> new ArrayDeque<>());
        synchronized (q) {
            while (!q.isEmpty() && q.peekFirst() <= now - windowNanos) {
                q.pollFirst();
            }
            if (q.size() >= maxRequests) {
                return false;
            }
            q.addLast(now);
            return true;
        }
    }

    public void clear() {
        hits.clear();
    }
}
