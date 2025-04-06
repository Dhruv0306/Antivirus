package com.antivirus.service;

import com.antivirus.model.BlockedDomain;
import com.antivirus.repository.BlockedDomainRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.Map;
import java.util.HashMap;

/**
 * Service that handles domain blocking through a proxy server
 * This provides real-time blocking without requiring system-level changes
 */
@Service
public class ProxyDomainBlockingService {
    private static final Logger logger = LoggerFactory.getLogger(ProxyDomainBlockingService.class);
    private static final int DEFAULT_PROXY_PORT = 8081;
    
    @Autowired
    private BlockedDomainRepository blockedDomainRepository;
    
    private ServerSocket serverSocket;
    private final ExecutorService executorService = Executors.newCachedThreadPool();
    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    private int proxyPort = DEFAULT_PROXY_PORT;
    
    /**
     * Start the proxy server
     */
    public void startProxyServer() {
        if (isRunning.get()) {
            logger.info("Proxy server is already running on port {}", proxyPort);
            return;
        }
        
        try {
            serverSocket = new ServerSocket(proxyPort);
            isRunning.set(true);
            
            // Start accepting connections in a separate thread
            executorService.submit(this::acceptConnections);
            
            logger.info("Proxy server started on port {}", proxyPort);
        } catch (IOException e) {
            logger.error("Failed to start proxy server: {}", e.getMessage());
            throw new RuntimeException("Failed to start proxy server", e);
        }
    }
    
    /**
     * Stop the proxy server
     */
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
            executorService.shutdown();
            logger.info("Proxy server stopped");
        } catch (IOException e) {
            logger.error("Error stopping proxy server: {}", e.getMessage());
        }
    }
    
    /**
     * Accept client connections
     */
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
    
    /**
     * Handle client connection
     */
    private void handleClientConnection(Socket clientSocket) {
        try {
            // Check if the requested domain is blocked
            String requestedDomain = extractDomainFromRequest(clientSocket);
            if (isDomainBlocked(requestedDomain)) {
                // Send blocked response
                sendBlockedResponse(clientSocket);
            } else {
                // Forward the request to the actual server
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
    
    /**
     * Extract domain from client request
     */
    private String extractDomainFromRequest(Socket clientSocket) throws IOException {
        // This is a simplified implementation
        // In a real proxy, you would parse the HTTP request to get the Host header
        return "example.com"; // Placeholder
    }
    
    /**
     * Check if a domain is blocked
     */
    public boolean isDomainBlocked(String domain) {
        return blockedDomainRepository.findByDomain(domain)
            .map(BlockedDomain::isActive)
            .orElse(false);
    }
    
    /**
     * Send blocked response to client
     */
    private void sendBlockedResponse(Socket clientSocket) throws IOException {
        String response = "HTTP/1.1 403 Forbidden\r\n" +
                         "Content-Type: text/html\r\n" +
                         "Connection: close\r\n\r\n" +
                         "<html><body><h1>Access Denied</h1>" +
                         "<p>This domain has been blocked by the antivirus software.</p></body></html>";
        
        clientSocket.getOutputStream().write(response.getBytes());
    }
    
    /**
     * Forward request to actual server
     */
    private void forwardRequest(Socket clientSocket) throws IOException {
        // This is a simplified implementation
        // In a real proxy, you would:
        // 1. Parse the client request
        // 2. Create a new connection to the target server
        // 3. Forward the request
        // 4. Stream the response back to the client
    }
    
    /**
     * Check if proxy server is running
     */
    public boolean isProxyRunning() {
        return isRunning.get();
    }
    
    /**
     * Get proxy server port
     */
    public int getProxyPort() {
        return proxyPort;
    }
    
    /**
     * Get instructions for configuring system to use proxy
     */
    public Map<String, String> getProxyInstructions() {
        Map<String, String> instructions = new HashMap<>();
        
        // Windows instructions
        instructions.put("windows", 
            "1. Open Windows Settings\n" +
            "2. Go to Network & Internet > Proxy\n" +
            "3. Under Manual proxy setup, enable 'Use a proxy server'\n" +
            "4. Enter 'localhost' as Address and '" + proxyPort + "' as Port\n" +
            "5. Click Save");
            
        // macOS instructions
        instructions.put("macos",
            "1. Open System Preferences\n" +
            "2. Go to Network > Advanced > Proxies\n" +
            "3. Check 'Web Proxy (HTTP)'\n" +
            "4. Enter 'localhost' as Address and '" + proxyPort + "' as Port\n" +
            "5. Click OK");
            
        // Linux instructions
        instructions.put("linux",
            "1. Open System Settings\n" +
            "2. Go to Network > Network Proxy\n" +
            "3. Select 'Manual'\n" +
            "4. Enter 'localhost' as HTTP Proxy and '" + proxyPort + "' as Port\n" +
            "5. Click Apply");
            
        return instructions;
    }
} 