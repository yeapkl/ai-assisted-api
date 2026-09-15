package app;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;

/**
 * Authenticated Hello World API.
 * <p>
 * Run:    mvn compile exec:java -Dexec.mainClass=app.Main   (dev)
 * Or:     java -jar target/hello-world-api.jar               (packaged jar)
 */
public final class Main {

    private Main() {
    }

    public static void main(String[] args) throws IOException {
        Config config = Config.load();
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8000"));

        ApiServer apiServer = new ApiServer(config, new Store(), new RateLimiter());
        HttpServer server = apiServer.start(port);

        System.out.println("Authenticated Hello World API listening on http://0.0.0.0:" + port
                + " (APP_ENV=" + config.appEnv + ")");
        Runtime.getRuntime().addShutdownHook(new Thread(() -> server.stop(0)));
    }
}
