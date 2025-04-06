package com.antivirus.controller;

import com.antivirus.model.BlockedDomain;
import com.antivirus.model.NetworkScanResult;
import com.antivirus.service.NetworkSecurityService;
import com.antivirus.service.CompositeDomainBlockingService;
import com.antivirus.service.DomainBlockingService;
import com.antivirus.service.ProxyDomainBlockingService;
import com.antivirus.service.DnsDomainBlockingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.ArrayList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Controller for managing network security features
 */
@RestController
@RequestMapping("/api/network-security")
@CrossOrigin(
    origins = {"http://localhost:3000", "http://localhost:5000", "http://localhost:8080"},
    allowedHeaders = {"Origin", "Content-Type", "Accept", "Authorization", "Access-Control-Allow-Origin"},
    exposedHeaders = {"Access-Control-Allow-Origin"},
    methods = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE, RequestMethod.OPTIONS},
    allowCredentials = "true"
)
public class NetworkSecurityController {

    private static final Logger logger = LoggerFactory.getLogger(NetworkSecurityController.class);

    @Autowired
    private NetworkSecurityService networkSecurityService;

    @Autowired
    private CompositeDomainBlockingService domainBlockingService;

    @Autowired
    private DomainBlockingService hostsFileDomainBlockingService;
    
    @Autowired
    private ProxyDomainBlockingService proxyDomainBlockingService;
    
    @Autowired
    private DnsDomainBlockingService dnsDomainBlockingService;

    /**
     * Get the current status of network security features
     */
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getStatus() {
        Map<String, Object> response = new HashMap<>();
        
        // Add network status information
        response.put("activeConnections", networkSecurityService.getActiveConnections());
        response.put("blockedAttempts", networkSecurityService.getBlockedAttempts());
        
        // Add security controls status
        Map<String, Object> securityControls = new HashMap<>();
        securityControls.put("firewallEnabled", networkSecurityService.isFirewallEnabled());
        securityControls.put("webProtectionEnabled", networkSecurityService.isWebProtectionEnabled());
        response.put("securityControls", securityControls);
        
        // Get blocked domains from the service
        List<Map<String, Object>> blockedDomains = new ArrayList<>();
        try {
            List<BlockedDomain> domains = hostsFileDomainBlockingService.getBlockedDomains();
            for (BlockedDomain domain : domains) {
                Map<String, Object> domainInfo = new HashMap<>();
                domainInfo.put("domain", domain.getDomain());
                domainInfo.put("blockedAt", domain.getBlockedAt().toString());
                blockedDomains.add(domainInfo);
            }
        } catch (Exception e) {
            logger.error("Error getting blocked domains", e);
        }
        response.put("blockedDomains", blockedDomains);
        
        // Check hosts file accessibility
        boolean hostsFileAccessible = hostsFileDomainBlockingService.isHostsFileAccessible();
        boolean hasAdminPrivileges = hostsFileDomainBlockingService.isAdmin();
        
        response.put("hostsFileAccessible", hostsFileAccessible);
        response.put("hasAdminPrivileges", hasAdminPrivileges);
        
        // Check proxy server status
        boolean proxyRunning = proxyDomainBlockingService.isProxyRunning();
        response.put("proxyServerRunning", proxyRunning);
        if (proxyRunning) {
            response.put("proxyPort", proxyDomainBlockingService.getProxyPort());
        }
        
        // Check DNS blocking status
        boolean dnsConfigAccessible = dnsDomainBlockingService.isDnsConfigAccessible();
        response.put("dnsConfigAccessible", dnsConfigAccessible);
        
        // Add warning if hosts file is not accessible
        if (!hostsFileAccessible || !hasAdminPrivileges) {
            response.put("warning", "Hosts file is not accessible or application doesn't have administrator privileges. " +
                    "Domain blocking will be simulated in the database only. " +
                    "Consider using the proxy server or DNS blocking methods instead.");
        }
        
        return ResponseEntity.ok(response);
    }

    /**
     * Perform network security scan
     */
    @PostMapping("/scan")
    public ResponseEntity<NetworkScanResult> scanNetwork() {
        return ResponseEntity.ok(networkSecurityService.scanNetwork());
    }

    /**
     * Toggle firewall status
     */
    @PostMapping("/firewall/toggle")
    public ResponseEntity<Void> toggleFirewall(@RequestBody Map<String, Boolean> request) {
        networkSecurityService.toggleFirewall(request.get("enabled"));
        return ResponseEntity.ok().build();
    }

    /**
     * Toggle web protection status
     */
    @PostMapping("/web-protection/toggle")
    public ResponseEntity<Void> toggleWebProtection(@RequestBody Map<String, Boolean> request) {
        networkSecurityService.toggleWebProtection(request.get("enabled"));
        return ResponseEntity.ok().build();
    }

    /**
     * Block a domain
     */
    @PostMapping("/block")
    public ResponseEntity<Map<String, Object>> blockDomain(@RequestBody Map<String, String> request) {
        String domain = request.get("domain");
        String reason = request.get("reason");
        
        Map<String, Object> response = new HashMap<>();
        
        try {
            hostsFileDomainBlockingService.blockDomain(domain, reason);
            response.put("success", true);
            response.put("message", "Domain blocked successfully");
            
            // Add warning if hosts file is not accessible
            if (!hostsFileDomainBlockingService.isHostsFileAccessible() || !hostsFileDomainBlockingService.isAdmin()) {
                response.put("warning", "Domain will be blocked in database only. " +
                        "To enable system-wide blocking, run the application with administrator privileges " +
                        "or use alternative blocking methods (proxy/DNS).");
            }
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(response);
        }
    }

    /**
     * Unblock a domain
     */
    @PostMapping("/unblock")
    public ResponseEntity<Map<String, Object>> unblockDomain(@RequestBody Map<String, String> request) {
        String domain = request.get("domain");
        
        Map<String, Object> response = new HashMap<>();
        
        try {
            hostsFileDomainBlockingService.unblockDomain(domain);
            response.put("success", true);
            response.put("message", "Domain unblocked successfully");
            
            // Add warning if hosts file is not accessible
            if (!hostsFileDomainBlockingService.isHostsFileAccessible() || !hostsFileDomainBlockingService.isAdmin()) {
                response.put("warning", "Domain will be unblocked in database only. " +
                        "To enable system-wide unblocking, run the application with administrator privileges " +
                        "or use alternative blocking methods (proxy/DNS).");
            }
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(response);
        }
    }

    /**
     * Get list of blocked domains
     */
    @GetMapping("/blocked")
    public ResponseEntity<List<BlockedDomain>> getBlockedDomains() {
        return ResponseEntity.ok(hostsFileDomainBlockingService.getBlockedDomains());
    }
    
    /**
     * Start the proxy server for domain blocking
     */
    @PostMapping("/proxy/start")
    public ResponseEntity<Map<String, Object>> startProxyServer() {
        Map<String, Object> response = new HashMap<>();
        
        try {
            proxyDomainBlockingService.startProxyServer();
            response.put("success", true);
            response.put("message", "Proxy server started successfully");
            response.put("port", proxyDomainBlockingService.getProxyPort());
            response.put("instructions", proxyDomainBlockingService.getProxyInstructions());
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(response);
        }
    }
    
    /**
     * Stop the proxy server
     */
    @PostMapping("/proxy/stop")
    public ResponseEntity<Map<String, Object>> stopProxyServer() {
        Map<String, Object> response = new HashMap<>();
        
        try {
            proxyDomainBlockingService.stopProxyServer();
            response.put("success", true);
            response.put("message", "Proxy server stopped successfully");
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(response);
        }
    }
    
    /**
     * Get proxy server status
     */
    @GetMapping("/proxy/status")
    public ResponseEntity<Map<String, Object>> getProxyStatus() {
        Map<String, Object> response = new HashMap<>();
        
        boolean isRunning = proxyDomainBlockingService.isProxyRunning();
        response.put("running", isRunning);
        
        if (isRunning) {
            response.put("port", proxyDomainBlockingService.getProxyPort());
            response.put("instructions", proxyDomainBlockingService.getProxyInstructions());
        }
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Update DNS configuration for domain blocking
     */
    @PostMapping("/dns/update")
    public ResponseEntity<Map<String, Object>> updateDnsConfig() {
        Map<String, Object> response = new HashMap<>();
        
        try {
            if (!dnsDomainBlockingService.isDnsConfigAccessible()) {
                response.put("success", false);
                response.put("error", "DNS configuration file is not accessible. Run the application with administrator privileges.");
                return ResponseEntity.badRequest().body(response);
            }
            
            dnsDomainBlockingService.updateDnsConfig();
            response.put("success", true);
            response.put("message", "DNS configuration updated successfully");
            response.put("instructions", dnsDomainBlockingService.getDnsInstructions());
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("success", false);
            response.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(response);
        }
    }
    
    /**
     * Get alternative domain blocking methods
     */
    @GetMapping("/blocking-methods")
    public ResponseEntity<Map<String, Object>> getAlternativeDomainBlockingMethods() {
        Map<String, Object> response = new HashMap<>();
        
        // Check current status
        boolean hostsFileAccessible = hostsFileDomainBlockingService.isHostsFileAccessible();
        boolean hasAdminPrivileges = hostsFileDomainBlockingService.isAdmin();
        boolean proxyRunning = proxyDomainBlockingService.isProxyRunning();
        boolean dnsConfigAccessible = dnsDomainBlockingService.isDnsConfigAccessible();
        
        // Add status information
        response.put("hostsFileMethod", Map.of(
            "available", hostsFileAccessible && hasAdminPrivileges,
            "requiresAdmin", true,
            "description", "Modifies the hosts file to redirect blocked domains to localhost"
        ));
        
        response.put("proxyMethod", Map.of(
            "available", true,
            "running", proxyRunning,
            "port", proxyDomainBlockingService.getProxyPort(),
            "description", "Uses a local proxy server to block access to malicious domains"
        ));
        
        response.put("dnsMethod", Map.of(
            "available", dnsConfigAccessible,
            "requiresAdmin", true,
            "description", "Configures DNS settings to block access to malicious domains"
        ));
        
        // Add recommendations
        if (!hostsFileAccessible || !hasAdminPrivileges) {
            response.put("recommendation", "Since hosts file modification is not available, " +
                    "we recommend using the proxy server method which doesn't require administrator privileges.");
        }
        
        return ResponseEntity.ok(response);
    }
} 