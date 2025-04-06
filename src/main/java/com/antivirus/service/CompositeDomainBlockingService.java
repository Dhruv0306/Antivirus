package com.antivirus.service;

import com.antivirus.model.BlockedDomain;
import com.antivirus.repository.BlockedDomainRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.scheduling.annotation.Scheduled;

import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Service that coordinates between different domain blocking methods
 * to provide maximum security through multiple layers of protection
 */
@Service
public class CompositeDomainBlockingService {
    private static final Logger logger = LoggerFactory.getLogger(CompositeDomainBlockingService.class);
    
    @Autowired
    private DomainBlockingService hostsBlockingService;
    
    @Autowired
    private ProxyDomainBlockingService proxyBlockingService;
    
    @Autowired
    private DnsDomainBlockingService dnsBlockingService;
    
    @Autowired
    private BlockedDomainRepository blockedDomainRepository;
    
    private final AtomicBoolean isInitialized = new AtomicBoolean(false);
    
    /**
     * Initialize all available blocking methods
     */
    public void initialize() {
        if (isInitialized.get()) {
            return;
        }
        
        try {
            // Try to initialize hosts file blocking
            if (hostsBlockingService.isHostsFileAccessible()) {
                logger.info("Hosts file blocking initialized");
            }
            
            // Initialize proxy server
            if (!proxyBlockingService.isProxyRunning()) {
                proxyBlockingService.startProxyServer();
                logger.info("Proxy server initialized");
            }
            
            // Try to initialize DNS blocking
            if (dnsBlockingService.isDnsConfigAccessible()) {
                dnsBlockingService.updateDnsConfig();
                logger.info("DNS blocking initialized");
            }
            
            isInitialized.set(true);
            logger.info("All available blocking methods initialized");
        } catch (Exception e) {
            logger.error("Error initializing blocking methods: {}", e.getMessage());
        }
    }
    
    /**
     * Block a domain using all available methods
     */
    public void blockDomain(String domain, String reason) {
        // First, save to database
        BlockedDomain blockedDomain = new BlockedDomain(domain);
        blockedDomain.setReason(reason);
        blockedDomainRepository.save(blockedDomain);
        
        // Try hosts file blocking if available
        if (hostsBlockingService.isHostsFileAccessible()) {
            try {
                hostsBlockingService.blockDomain(domain, reason);
                logger.info("Domain {} blocked via hosts file", domain);
            } catch (Exception e) {
                logger.warn("Failed to block domain {} via hosts file: {}", domain, e.getMessage());
            }
        }
        
        // Update DNS config if available
        if (dnsBlockingService.isDnsConfigAccessible()) {
            try {
                dnsBlockingService.updateDnsConfig();
                logger.info("DNS config updated for domain {}", domain);
            } catch (Exception e) {
                logger.warn("Failed to update DNS config for domain {}: {}", domain, e.getMessage());
            }
        }
        
        // Proxy server is already running and will block the domain automatically
        logger.info("Domain {} blocked via proxy server", domain);
    }
    
    /**
     * Unblock a domain from all methods
     */
    public void unblockDomain(String domain) {
        // First, update database
        blockedDomainRepository.findByDomain(domain).ifPresent(blockedDomain -> {
            blockedDomain.setActive(false);
            blockedDomainRepository.save(blockedDomain);
        });
        
        // Try hosts file unblocking if available
        if (hostsBlockingService.isHostsFileAccessible()) {
            try {
                hostsBlockingService.unblockDomain(domain);
                logger.info("Domain {} unblocked via hosts file", domain);
            } catch (Exception e) {
                logger.warn("Failed to unblock domain {} via hosts file: {}", domain, e.getMessage());
            }
        }
        
        // Update DNS config if available
        if (dnsBlockingService.isDnsConfigAccessible()) {
            try {
                dnsBlockingService.updateDnsConfig();
                logger.info("DNS config updated to unblock domain {}", domain);
            } catch (Exception e) {
                logger.warn("Failed to update DNS config to unblock domain {}: {}", domain, e.getMessage());
            }
        }
        
        // Proxy server will automatically allow the domain
        logger.info("Domain {} unblocked via proxy server", domain);
    }
    
    /**
     * Get status of all blocking methods
     */
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new HashMap<>();
        
        // Hosts file status
        status.put("hostsFileAccessible", hostsBlockingService.isHostsFileAccessible());
        status.put("isAdmin", hostsBlockingService.isAdmin());
        
        // Proxy server status
        status.put("proxyRunning", proxyBlockingService.isProxyRunning());
        status.put("proxyPort", proxyBlockingService.getProxyPort());
        
        // DNS status
        status.put("dnsConfigAccessible", dnsBlockingService.isDnsConfigAccessible());
        
        // Get active blocking methods
        List<String> activeMethods = new ArrayList<>();
        if (hostsBlockingService.isHostsFileAccessible()) {
            activeMethods.add("hosts_file");
        }
        if (proxyBlockingService.isProxyRunning()) {
            activeMethods.add("proxy_server");
        }
        if (dnsBlockingService.isDnsConfigAccessible()) {
            activeMethods.add("dns");
        }
        status.put("activeMethods", activeMethods);
        
        // Get security recommendations
        List<String> recommendations = new ArrayList<>();
        if (!hostsBlockingService.isHostsFileAccessible()) {
            recommendations.add("Run with administrator privileges to enable hosts file blocking");
        }
        if (!proxyBlockingService.isProxyRunning()) {
            recommendations.add("Start the proxy server for additional protection");
        }
        if (!dnsBlockingService.isDnsConfigAccessible()) {
            recommendations.add("Configure DNS settings for system-wide blocking");
        }
        status.put("recommendations", recommendations);
        
        return status;
    }
    
    /**
     * Synchronize all blocking methods every 5 minutes
     */
    @Scheduled(fixedRate = 300000) // 5 minutes
    public void synchronizeBlockingMethods() {
        logger.info("Synchronizing blocking methods...");
        
        // Get all active blocked domains
        List<BlockedDomain> activeDomains = blockedDomainRepository.findByActiveTrue();
        
        // Update hosts file if accessible
        if (hostsBlockingService.isHostsFileAccessible()) {
            try {
                hostsBlockingService.synchronizeHostsFile();
                logger.info("Hosts file synchronized");
            } catch (Exception e) {
                logger.warn("Failed to synchronize hosts file: {}", e.getMessage());
            }
        }
        
        // Update DNS config if accessible
        if (dnsBlockingService.isDnsConfigAccessible()) {
            try {
                dnsBlockingService.updateDnsConfig();
                logger.info("DNS config synchronized");
            } catch (Exception e) {
                logger.warn("Failed to synchronize DNS config: {}", e.getMessage());
            }
        }
        
        // Proxy server automatically handles domain blocking
        logger.info("Blocking methods synchronized");
    }

    /**
     * Get all blocked domains
     */
    public List<BlockedDomain> getBlockedDomains() {
        return blockedDomainRepository.findByActiveTrue();
    }
} 