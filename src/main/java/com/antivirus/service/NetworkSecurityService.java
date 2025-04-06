package com.antivirus.service;

import com.antivirus.model.NetworkScanResult;
import java.util.Map;

/**
 * Service interface for network security operations
 */
public interface NetworkSecurityService {
    /**
     * Perform a network security scan
     * @return NetworkScanResult containing scan findings
     */
    NetworkScanResult scanNetwork();

    /**
     * Get current network security status
     * @return Map containing network status information
     */
    Map<String, Object> getNetworkStatus();

    /**
     * Toggle firewall status
     * @param enabled true to enable, false to disable
     */
    void toggleFirewall(Boolean enabled);

    /**
     * Toggle web protection status
     * @param enabled true to enable, false to disable
     */
    void toggleWebProtection(Boolean enabled);

    /**
     * Add domain to block list
     * @param domain domain name to block
     */
    void blockDomain(String domain);

    /**
     * Remove domain from block list
     * @param domain domain name to unblock
     */
    void unblockDomain(String domain);

    /**
     * Check if firewall is enabled
     */
    boolean isFirewallEnabled();

    /**
     * Check if web protection is enabled
     */
    boolean isWebProtectionEnabled();

    /**
     * Get number of active connections
     */
    int getActiveConnections();

    /**
     * Get number of blocked attempts
     */
    int getBlockedAttempts();

    /**
     * Increment blocked attempts counter
     */
    void incrementBlockedAttempts();

    /**
     * Update active connections count
     */
    void updateActiveConnections(int connections);
} 