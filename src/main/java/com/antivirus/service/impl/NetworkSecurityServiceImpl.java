package com.antivirus.service.impl;

import com.antivirus.model.NetworkScanResult;
import com.antivirus.model.NetworkVulnerability;
import com.antivirus.service.NetworkSecurityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

/**
 * Implementation of network security service with enhanced scanning capabilities
 */
@Service
public class NetworkSecurityServiceImpl implements NetworkSecurityService {
    private static final Logger logger = LoggerFactory.getLogger(NetworkSecurityServiceImpl.class);
    
    // Security control flags
    private boolean firewallEnabled = true;
    private boolean webProtectionEnabled = true;
    
    // Network monitoring data structures
    private Set<String> blockedDomains = ConcurrentHashMap.newKeySet();
    private List<Map<String, Object>> recentConnections = new CopyOnWriteArrayList<>();
    private Map<String, Integer> connectionAttempts = new ConcurrentHashMap<>();
    private Map<String, LocalDateTime> lastConnectionTime = new ConcurrentHashMap<>();
    
    // Counters
    private AtomicInteger blockedAttempts = new AtomicInteger(0);
    private AtomicInteger activeConnections = new AtomicInteger(0);
    private AtomicInteger activeThreats = new AtomicInteger(0);
    
    // Configuration constants
    private static final int[] COMMON_PORTS = {
        20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1433, 1521, 
        3306, 3389, 5432, 8080, 8443
    };
    
    private static final int MAX_CONNECTION_ATTEMPTS = 5;
    private static final int CONNECTION_TIMEOUT_MS = 1000;
    private static final int RATE_LIMIT_WINDOW_SECONDS = 60;

    @PostConstruct
    public void init() {
        // Initialize with common malicious domains
        blockedDomains.addAll(Arrays.asList(
            "malware.example.com",
            "phishing.example.com",
            "spam.example.com"
        ));
        
        // Start background monitoring
        startNetworkMonitoring();
    }

    @Override
    public NetworkScanResult scanNetwork() {
        logger.info("Starting comprehensive network security scan");
        List<NetworkVulnerability> vulnerabilities = new ArrayList<>();
        int threats = 0;

        // Scan network interfaces
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface iface = interfaces.nextElement();
                if (iface.isUp() && !iface.isLoopback()) {
                    // Check interface security
                    if (!iface.isPointToPoint()) {
                        NetworkVulnerability vulnerability = new NetworkVulnerability();
                        vulnerability.setType("NETWORK_INTERFACE");
                        vulnerability.setDescription("Network interface " + iface.getDisplayName() + " is active");
                        vulnerability.setSeverity("LOW");
                        vulnerability.setRecommendation("Monitor interface for suspicious activity");
                        vulnerabilities.add(vulnerability);
                    }
                }
            }
        } catch (IOException e) {
            logger.error("Error scanning network interfaces", e);
        }

        // Enhanced port scanning
        for (int port : COMMON_PORTS) {
            if (isPortOpen("localhost", port)) {
                NetworkVulnerability vulnerability = new NetworkVulnerability();
                vulnerability.setType("OPEN_PORT");
                vulnerability.setDescription("Port " + port + " is open and potentially vulnerable");
                vulnerability.setSeverity(getPortSeverity(port));
                vulnerability.setRecommendation(getPortRecommendation(port));
                vulnerabilities.add(vulnerability);
                threats++;
            }
        }

        // Check security controls
        if (!firewallEnabled) {
            addSecurityControlVulnerability(vulnerabilities, "FIREWALL_DISABLED", "CRITICAL");
            threats++;
        }

        if (!webProtectionEnabled) {
            addSecurityControlVulnerability(vulnerabilities, "WEB_PROTECTION_DISABLED", "HIGH");
            threats++;
        }

        // Check for suspicious connections
        List<String> suspiciousIPs = getSuspiciousConnections();
        if (!suspiciousIPs.isEmpty()) {
            NetworkVulnerability vulnerability = new NetworkVulnerability();
            vulnerability.setType("SUSPICIOUS_CONNECTIONS");
            vulnerability.setDescription("Detected " + suspiciousIPs.size() + " suspicious connections");
            vulnerability.setSeverity("HIGH");
            vulnerability.setRecommendation("Investigate and block suspicious IPs");
            vulnerabilities.add(vulnerability);
            threats += suspiciousIPs.size();
        }

        // Create scan result
        NetworkScanResult result = new NetworkScanResult();
        result.setThreats(threats);
        result.setVulnerabilities(vulnerabilities);
        result.setScanTime(LocalDateTime.now());
        result.setStatus("COMPLETED");
        result.setOpenPorts(getOpenPorts());
        result.setSuspiciousConnections(suspiciousIPs);
        result.setFirewallEnabled(firewallEnabled);
        result.setWebProtectionEnabled(webProtectionEnabled);
        result.setActiveThreats(activeThreats.get());
        result.setBlockedAttempts(blockedAttempts.get());

        logger.info("Network scan completed. Found {} threats", threats);
        return result;
    }

    @Override
    public Map<String, Object> getNetworkStatus() {
        Map<String, Object> status = new HashMap<>();
        
        // Add security controls status in the expected structure
        Map<String, Object> securityControls = new HashMap<>();
        securityControls.put("firewallEnabled", firewallEnabled);
        securityControls.put("webProtectionEnabled", webProtectionEnabled);
        status.put("securityControls", securityControls);
        
        // Add network statistics
        status.put("activeConnections", activeConnections.get());
        status.put("blockedAttempts", blockedAttempts.get());
        
        // Add blocked domains list
        List<Map<String, Object>> blockedDomainsList = new ArrayList<>();
        for (String domain : blockedDomains) {
            Map<String, Object> domainInfo = new HashMap<>();
            domainInfo.put("domain", domain);
            domainInfo.put("blockedAt", LocalDateTime.now().toString());
            blockedDomainsList.add(domainInfo);
        }
        status.put("blockedDomains", blockedDomainsList);
        
        // Add active threats and recent connections
        status.put("activeThreats", activeThreats.get());
        status.put("recentConnections", recentConnections);
        
        return status;
    }

    @Override
    public void toggleFirewall(Boolean enabled) {
        logger.info("Toggling firewall: {}", enabled);
        this.firewallEnabled = enabled != null ? enabled : !this.firewallEnabled;
        if (this.firewallEnabled) {
            activeThreats.decrementAndGet();
        } else {
            activeThreats.incrementAndGet();
        }
    }

    @Override
    public void toggleWebProtection(Boolean enabled) {
        logger.info("Toggling web protection: {}", enabled);
        this.webProtectionEnabled = enabled != null ? enabled : !this.webProtectionEnabled;
        if (this.webProtectionEnabled) {
            activeThreats.decrementAndGet();
        } else {
            activeThreats.incrementAndGet();
        }
    }

    @Override
    public void blockDomain(String domain) {
        logger.info("Blocking domain: {}", domain);
        blockedDomains.add(domain.toLowerCase());
        // Simulate blocking effect
        blockedAttempts.incrementAndGet();
    }

    @Override
    public void unblockDomain(String domain) {
        logger.info("Unblocking domain: {}", domain);
        blockedDomains.remove(domain.toLowerCase());
    }

    @Override
    public boolean isFirewallEnabled() {
        return firewallEnabled;
    }

    @Override
    public boolean isWebProtectionEnabled() {
        return webProtectionEnabled;
    }

    @Override
    public int getActiveConnections() {
        return activeConnections.get();
    }

    @Override
    public int getBlockedAttempts() {
        return blockedAttempts.get();
    }

    @Override
    public void incrementBlockedAttempts() {
        blockedAttempts.incrementAndGet();
    }

    @Override
    public void updateActiveConnections(int connections) {
        activeConnections.set(connections);
    }

    private boolean isPortOpen(String host, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), 1000);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private List<String> getOpenPorts() {
        List<String> openPorts = new ArrayList<>();
        for (int port : COMMON_PORTS) {
            if (isPortOpen("localhost", port)) {
                openPorts.add(String.valueOf(port));
            }
        }
        return openPorts;
    }

    private List<String> getSuspiciousConnections() {
        // Simulate suspicious connections detection
        List<String> suspicious = new ArrayList<>();
        if (!firewallEnabled || !webProtectionEnabled) {
            suspicious.add("192.168.1.100");
        }
        return suspicious;
    }

    private void startNetworkMonitoring() {
        // Start a background thread for continuous monitoring
        Thread monitorThread = new Thread(() -> {
            while (true) {
                try {
                    // Monitor active connections
                    updateActiveConnections(getCurrentActiveConnections());
                    
                    // Check for suspicious activities
                    checkSuspiciousActivities();
                    
                    // Clean up old connection records
                    cleanupOldConnections();
                    
                    Thread.sleep(5000); // Check every 5 seconds
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        });
        monitorThread.setDaemon(true);
        monitorThread.start();
    }

    private void checkSuspiciousActivities() {
        LocalDateTime now = LocalDateTime.now();
        connectionAttempts.forEach((ip, attempts) -> {
            if (attempts > MAX_CONNECTION_ATTEMPTS) {
                logger.warn("Suspicious activity detected from IP: {}", ip);
                blockedAttempts.incrementAndGet();
                activeThreats.incrementAndGet();
            }
        });
    }

    private void cleanupOldConnections() {
        LocalDateTime cutoff = LocalDateTime.now().minusSeconds(RATE_LIMIT_WINDOW_SECONDS);
        lastConnectionTime.entrySet().removeIf(entry -> entry.getValue().isBefore(cutoff));
        connectionAttempts.entrySet().removeIf(entry -> 
            !lastConnectionTime.containsKey(entry.getKey()) || 
            lastConnectionTime.get(entry.getKey()).isBefore(cutoff)
        );
    }

    private int getCurrentActiveConnections() {
        try {
            return (int) NetworkInterface.getNetworkInterfaces()
                .asIterator()
                .next()
                .getInterfaceAddresses()
                .size();
        } catch (Exception e) {
            logger.error("Error getting active connections", e);
            return 0;
        }
    }

    private String getPortSeverity(int port) {
        if (port < 1024) return "HIGH";
        if (port == 3389 || port == 22 || port == 23) return "MEDIUM";
        return "LOW";
    }

    private String getPortRecommendation(int port) {
        switch (port) {
            case 3389: return "Restrict RDP access to trusted IPs only";
            case 22: return "Use SSH key authentication and disable password login";
            case 23: return "Disable Telnet and use SSH instead";
            default: return "Close unnecessary ports or restrict access";
        }
    }

    private void addSecurityControlVulnerability(List<NetworkVulnerability> vulnerabilities, 
                                               String type, String severity) {
        NetworkVulnerability vulnerability = new NetworkVulnerability();
        vulnerability.setType(type);
        vulnerability.setDescription(type.replace("_", " ").toLowerCase() + " is currently disabled");
        vulnerability.setSeverity(severity);
        vulnerability.setRecommendation("Enable " + type.replace("_", " ").toLowerCase() + " protection");
        vulnerabilities.add(vulnerability);
    }
} 