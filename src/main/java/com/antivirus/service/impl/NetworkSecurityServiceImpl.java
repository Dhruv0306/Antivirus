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
import java.net.Socket;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Implementation of network security service
 */
@Service
public class NetworkSecurityServiceImpl implements NetworkSecurityService {
    private static final Logger logger = LoggerFactory.getLogger(NetworkSecurityServiceImpl.class);
    
    private boolean firewallEnabled = true;
    private boolean webProtectionEnabled = true;
    private Set<String> blockedDomains = ConcurrentHashMap.newKeySet();
    private List<Map<String, String>> recentConnections = new CopyOnWriteArrayList<>();
    private AtomicInteger blockedAttempts = new AtomicInteger(0);
    private AtomicInteger activeConnections = new AtomicInteger(0);
    private AtomicInteger activeThreats = new AtomicInteger(0);

    private static final int[] COMMON_PORTS = {80, 443, 8080, 21, 22, 23, 25, 53, 3306, 3389};

    @PostConstruct
    public void init() {
        // Add some common malicious domains to block list
        blockedDomains.addAll(Arrays.asList(
            "malware.example.com",
            "phishing.example.com",
            "spam.example.com"
        ));
    }

    @Override
    public NetworkScanResult scanNetwork() {
        logger.info("Starting network security scan");
        List<NetworkVulnerability> vulnerabilities = new ArrayList<>();
        int threats = 0;

        // Check common ports
        for (int port : COMMON_PORTS) {
            if (isPortOpen("localhost", port)) {
                NetworkVulnerability vulnerability = new NetworkVulnerability();
                vulnerability.setType("OPEN_PORT");
                vulnerability.setDescription("Port " + port + " is open and potentially vulnerable");
                vulnerability.setSeverity(port < 1024 ? "HIGH" : "MEDIUM");
                vulnerability.setRecommendation("Close unnecessary ports or restrict access");
                vulnerabilities.add(vulnerability);
                threats++;
            }
        }

        // Check firewall status
        if (!firewallEnabled) {
            NetworkVulnerability vulnerability = new NetworkVulnerability();
            vulnerability.setType("FIREWALL_DISABLED");
            vulnerability.setDescription("Firewall protection is currently disabled");
            vulnerability.setSeverity("CRITICAL");
            vulnerability.setRecommendation("Enable firewall protection");
            vulnerabilities.add(vulnerability);
            threats++;
        }

        // Check web protection
        if (!webProtectionEnabled) {
            NetworkVulnerability vulnerability = new NetworkVulnerability();
            vulnerability.setType("WEB_PROTECTION_DISABLED");
            vulnerability.setDescription("Web protection is currently disabled");
            vulnerability.setSeverity("HIGH");
            vulnerability.setRecommendation("Enable web protection");
            vulnerabilities.add(vulnerability);
            threats++;
        }

        NetworkScanResult result = new NetworkScanResult();
        result.setThreats(threats);
        result.setVulnerabilities(vulnerabilities);
        result.setScanTime(LocalDateTime.now());
        result.setStatus("COMPLETED");
        result.setOpenPorts(getOpenPorts());
        result.setSuspiciousConnections(getSuspiciousConnections());
        result.setFirewallEnabled(firewallEnabled);
        result.setWebProtectionEnabled(webProtectionEnabled);

        logger.info("Network scan completed. Found {} threats", threats);
        return result;
    }

    @Override
    public Map<String, Object> getNetworkStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("firewallEnabled", firewallEnabled);
        status.put("webProtectionEnabled", webProtectionEnabled);
        status.put("activeThreats", activeThreats.get());
        status.put("activeConnections", activeConnections.get());
        status.put("blockedAttempts", blockedAttempts.get());
        status.put("blockedDomains", new ArrayList<>(blockedDomains));
        status.put("recentConnections", recentConnections);
        return status;
    }

    @Override
    public void toggleFirewall(boolean enabled) {
        logger.info("Toggling firewall: {}", enabled);
        this.firewallEnabled = enabled;
        if (enabled) {
            activeThreats.decrementAndGet();
        } else {
            activeThreats.incrementAndGet();
        }
    }

    @Override
    public void toggleWebProtection(boolean enabled) {
        logger.info("Toggling web protection: {}", enabled);
        this.webProtectionEnabled = enabled;
        if (enabled) {
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
} 