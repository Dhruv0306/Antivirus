package com.antivirus.service;

import com.antivirus.model.BlockedDomain;
import com.antivirus.repository.BlockedDomainRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Service that handles domain blocking through a local-only proxy server.
 */
@Service
public class ProxyDomainBlockingService {
    private static final Logger logger = LoggerFactory.getLogger(ProxyDomainBlockingService.class);
    private static final int DEFAULT_PROXY_PORT = 8081;
    private static final int MAX_PROXY_THREADS = 50;
    private static final String LOCALHOST = "127.0.0.1";

    @Autowired
    private BlockedDomainRepository blockedDomainRepository;

    private ServerSocket serverSocket;
    private ExecutorService executorService;
    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    private int proxyPort = DEFAULT_PROXY_PORT;

    public void startProxyServer() {
        if (isRunning.get()) {
            logger.info("Proxy server is already running on port {}", proxyPort);
            return;
        }

        try {
            serverSocket = new ServerSocket();
            serverSocket.bind(new InetSocketAddress(LOCALHOST, proxyPort));
            executorService = Executors.newFixedThreadPool(MAX_PROXY_THREADS);
            isRunning.set(true);

            executorService.submit(this::acceptConnections);

            logger.info("Proxy server started on {}:{}", LOCALHOST, proxyPort);
        } catch (IOException e) {
            logger.error("Failed to start proxy server: {}", e.getMessage());
            throw new RuntimeException("Failed to start proxy server", e);
        }
    }

    public void stopProxyServer() {
        if (!isRunning.get()) {
            logger.info("Proxy server is not running");
            return;
        }

        try {
            isRunning.set(false);
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
            if (executorService != null) {
                executorService.shutdownNow();
                executorService = null;
            }
            logger.info("Proxy server stopped");
        } catch (IOException e) {
            logger.error("Error stopping proxy server: {}", e.getMessage());
        }
    }

    private void acceptConnections() {
        while (isRunning.get()) {
            try {
                Socket clientSocket = serverSocket.accept();
                executorService.submit(() -> handleClientConnection(clientSocket));
            } catch (IOException e) {
                if (isRunning.get()) {
                    logger.error("Error accepting connection: {}", e.getMessage());
                }
            }
        }
    }

    private void handleClientConnection(Socket clientSocket) {
        try {
            String requestedDomain = extractDomainFromRequest(clientSocket);
            if (isDomainBlocked(requestedDomain)) {
                sendBlockedResponse(clientSocket);
            } else {
                forwardRequest(clientSocket);
            }
        } catch (IOException e) {
            logger.error("Error handling client connection: {}", e.getMessage());
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                logger.error("Error closing client socket: {}", e.getMessage());
            }
        }
    }

    private String extractDomainFromRequest(Socket clientSocket) throws IOException {
        return "example.com";
    }

    public boolean isDomainBlocked(String domain) {
        return blockedDomainRepository.findByDomain(domain)
            .map(BlockedDomain::isActive)
            .orElse(false);
    }

    private void sendBlockedResponse(Socket clientSocket) throws IOException {
        String response = "HTTP/1.1 403 Forbidden\r\n" +
                         "Content-Type: text/html\r\n" +
                         "Connection: close\r\n\r\n" +
                         "<html><body><h1>Access Denied</h1>" +
                         "<p>This domain has been blocked by the antivirus software.</p></body></html>";

        clientSocket.getOutputStream().write(response.getBytes());
    }

    private void forwardRequest(Socket clientSocket) throws IOException {
        // Placeholder for full proxy forwarding implementation
    }

    public boolean isProxyRunning() {
        return isRunning.get();
    }

    public int getProxyPort() {
        return proxyPort;
    }

    public Map<String, String> getProxyInstructions() {
        Map<String, String> instructions = new HashMap<>();

        instructions.put("windows",
            "1. Open Windows Settings\n" +
            "2. Go to Network & Internet > Proxy\n" +
            "3. Under Manual proxy setup, enable 'Use a proxy server'\n" +
            "4. Enter '127.0.0.1' as Address and '" + proxyPort + "' as Port\n" +
            "5. Click Save");

        instructions.put("macos",
            "1. Open System Preferences\n" +
            "2. Go to Network > Advanced > Proxies\n" +
            "3. Check 'Web Proxy (HTTP)'\n" +
            "4. Enter '127.0.0.1' as Address and '" + proxyPort + "' as Port\n" +
            "5. Click OK");

        instructions.put("linux",
            "1. Open System Settings\n" +
            "2. Go to Network > Network Proxy\n" +
            "3. Select 'Manual'\n" +
            "4. Enter '127.0.0.1' as HTTP Proxy and '" + proxyPort + "' as Port\n" +
            "5. Click Apply");

        return instructions;
    }
}
