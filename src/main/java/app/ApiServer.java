package app;

import com.sun.net.httpserver.Filter;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

/** Authenticated Hello World API: register -> login (JWT access + refresh) -> protected /hello. */
public final class ApiServer {

    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_]+$");

    private final Config config;
    private final Store store;
    private final RateLimiter rateLimiter;
    private final String dummyHash;
    private final Filter securityHeadersFilter = new SecurityHeadersFilter();

    public ApiServer(Config config, Store store, RateLimiter rateLimiter) {
        this.config = config;
        this.store = store;
        this.rateLimiter = rateLimiter;
        // Fixed dummy hash used to equalize login timing for unknown usernames
        // (see handleLogin) — the password it "hashes" is never used to log in.
        this.dummyHash = Security.hashPassword(Security.randomHex(32));
    }

    /** Binds, wires up all routes, and starts the server on the given port (0 for an ephemeral port). */
    public HttpServer start(int port) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());

        List<com.sun.net.httpserver.HttpContext> contexts = List.of(
                server.createContext("/health", safe(this::handleHealth)),
                server.createContext("/api/v1/auth/register", safe(this::handleRegister)),
                server.createContext("/api/v1/auth/login", safe(this::handleLogin)),
                server.createContext("/api/v1/auth/refresh", safe(this::handleRefresh)),
                server.createContext("/api/v1/hello", safe(this::handleHello)));
        contexts.forEach(ctx -> ctx.getFilters().add(securityHeadersFilter));

        server.start();
        return server;
    }

    // --------------------------------------------------------------- endpoints

    private void handleHealth(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }
        sendJson(exchange, 200, Map.of("status", "ok"));
    }

    private void handleRegister(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }
        if (!checkRateLimit(exchange, "register", 5, 60)) {
            return;
        }

        Map<String, String> body = JsonUtil.parseFlatObjectSilently(readBody(exchange));
        String username = body.get("username");
        String password = body.get("password");

        String validationError = validateRegisterInput(username, password);
        if (validationError != null) {
            sendError(exchange, 422, validationError);
            return;
        }

        if (store.exists(username)) {
            // NFR-4: generic message, doesn't confirm the username is taken.
            sendError(exchange, 400, "Registration failed");
            return;
        }

        store.create(username, Security.hashPassword(password));
        sendJson(exchange, 201, Map.of("message", "User registered successfully"));
    }

    private void handleLogin(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }
        if (!checkRateLimit(exchange, "login", 10, 60)) {
            return;
        }

        Map<String, String> body = JsonUtil.parseFlatObjectSilently(readBody(exchange));
        String username = body.get("username");
        String password = body.get("password");
        if (username == null || password == null) {
            sendError(exchange, 422, "username and password are required");
            return;
        }

        Store.User user = store.get(username);
        // Pentest finding: always run the password hash comparison, even for a
        // nonexistent user, against a fixed dummy hash. Skipping it when the
        // user is unknown created a timing side-channel that let an attacker
        // enumerate valid usernames despite the identical error message.
        String hashedToCheck = user != null ? user.hashedPassword() : dummyHash;
        boolean passwordOk = Security.verifyPassword(password, hashedToCheck);

        if (user == null || !passwordOk) {
            // NFR-4: identical error whether the username or the password was wrong.
            sendError(exchange, 401, "Invalid credentials");
            return;
        }

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("access_token", Security.createToken(user.username(), "access", config));
        resp.put("refresh_token", Security.createToken(user.username(), "refresh", config));
        resp.put("token_type", "bearer");
        sendJson(exchange, 200, resp);
    }

    private void handleRefresh(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }
        if (!checkRateLimit(exchange, "refresh", 20, 60)) {
            return;
        }

        Map<String, String> body = JsonUtil.parseFlatObjectSilently(readBody(exchange));
        String refreshToken = body.get("refresh_token");
        if (refreshToken == null) {
            sendError(exchange, 422, "refresh_token: field required");
            return;
        }

        Security.TokenPayload payload;
        try {
            payload = Security.decodeToken(refreshToken, config);
        } catch (Security.TokenException e) {
            sendError(exchange, 401, "Invalid refresh token");
            return;
        }

        if (!"refresh".equals(payload.type())) {
            sendError(exchange, 401, "Invalid refresh token");
            return;
        }

        String username = payload.sub();
        if (username == null || username.isBlank() || !store.exists(username)) {
            sendError(exchange, 401, "Invalid refresh token");
            return;
        }

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("access_token", Security.createToken(username, "access", config));
        resp.put("token_type", "bearer");
        sendJson(exchange, 200, resp);
    }

    private void handleHello(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendError(exchange, 405, "Method not allowed");
            return;
        }

        String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            sendError(exchange, 401, "Could not validate credentials");
            return;
        }
        String token = authHeader.substring("Bearer ".length()).trim();

        Security.TokenPayload payload;
        try {
            payload = Security.decodeToken(token, config);
        } catch (Security.TokenException e) {
            sendError(exchange, 401, "Could not validate credentials");
            return;
        }

        if (!"access".equals(payload.type())) {
            sendError(exchange, 401, "Could not validate credentials");
            return;
        }

        String username = payload.sub();
        Store.User user = username != null ? store.get(username) : null;
        if (user == null) {
            sendError(exchange, 401, "Could not validate credentials");
            return;
        }

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("message", "Hello, " + user.username() + "!");
        resp.put("server_time_utc", Instant.now().toString());
        sendJson(exchange, 200, resp);
    }

    // ---------------------------------------------------------------- helpers

    private String validateRegisterInput(String username, String password) {
        if (username == null) {
            return "username: field required";
        }
        if (username.length() < 3 || username.length() > 32) {
            return "username: length must be between 3 and 32 characters";
        }
        if (!USERNAME_PATTERN.matcher(username).matches()) {
            return "username: must contain only letters, digits, and underscores";
        }
        if (password == null) {
            return "password: field required";
        }
        if (password.length() < 8 || password.length() > 128) {
            return "password: length must be between 8 and 128 characters";
        }
        return null;
    }

    private boolean checkRateLimit(HttpExchange exchange, String name, int max, int windowSeconds) throws IOException {
        String key = name + ":" + clientIp(exchange);
        if (!rateLimiter.isAllowed(key, max, windowSeconds)) {
            sendError(exchange, 429, "Too many requests. Please try again later.");
            return false;
        }
        return true;
    }

    private String clientIp(HttpExchange exchange) {
        String forwarded = exchange.getRequestHeaders().getFirst("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded;
        }
        if (exchange.getRemoteAddress() != null) {
            return exchange.getRemoteAddress().getAddress().getHostAddress();
        }
        return "unknown";
    }

    private String readBody(HttpExchange exchange) throws IOException {
        try (InputStream is = exchange.getRequestBody()) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private void sendJson(HttpExchange exchange, int status, Map<String, ?> body) throws IOException {
        byte[] bytes = JsonUtil.writeObject(body).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private void sendError(HttpExchange exchange, int status, String message) throws IOException {
        sendJson(exchange, status, Map.of("error", message));
    }

    /** Wraps a handler so an unexpected exception still yields a well-formed JSON response. */
    private HttpHandler safe(ThrowingHandler handler) {
        return exchange -> {
            try {
                handler.handle(exchange);
            } catch (Exception e) {
                try {
                    sendError(exchange, 500, "Internal server error");
                } catch (IOException ignored) {
                    // best-effort; the client already lost the connection
                }
            }
        };
    }

    @FunctionalInterface
    private interface ThrowingHandler {
        void handle(HttpExchange exchange) throws Exception;
    }

    /** NFR-6: baseline security headers on every response. */
    private final class SecurityHeadersFilter extends Filter {
        @Override
        public void doFilter(HttpExchange exchange, Chain chain) throws IOException {
            var headers = exchange.getResponseHeaders();
            headers.set("X-Content-Type-Options", "nosniff");
            headers.set("X-Frame-Options", "DENY");
            headers.set("Referrer-Policy", "no-referrer");
            headers.set("Cache-Control", "no-store");

            String origin = exchange.getRequestHeaders().getFirst("Origin");
            if (origin != null && config.corsOriginsList().contains(origin)) {
                headers.set("Access-Control-Allow-Origin", origin);
                headers.add("Vary", "Origin");
                headers.set("Access-Control-Allow-Headers", "Authorization, Content-Type");
                headers.set("Access-Control-Allow-Methods", "GET, POST");
            }
            if ("production".equals(config.appEnv)) {
                headers.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
            }
            chain.doFilter(exchange);
        }

        @Override
        public String description() {
            return "Baseline security headers";
        }
    }
}
