package edu.cyberdetect;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;

public final class Main {
    private Main() {}
    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getenv().getOrDefault("APP_PORT", "8080"));
        Database database = new Database();
        database.initialize();
        DetectionService detection = new DetectionService(database);
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
        server.createContext("/", new WebApp(database, detection));
        server.setExecutor(java.util.concurrent.Executors.newFixedThreadPool(12));
        server.start();
        System.out.printf("Cyber Attack Detection System running at http://localhost:%d%n", port);
        System.out.println("Demo login: admin / " + System.getenv().getOrDefault("ADMIN_PASSWORD", "admin123"));
    }
}
