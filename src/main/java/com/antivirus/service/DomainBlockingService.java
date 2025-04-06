package com.antivirus.service;

import com.antivirus.model.BlockedDomain;
import java.util.List;

/**
 * Service interface for hosts file-based domain blocking
 */
public interface DomainBlockingService {
    /**
     * Check if hosts file is accessible
     */
    boolean isHostsFileAccessible();
    
    /**
     * Block a domain by adding it to hosts file
     */
    void blockDomain(String domain, String reason);
    
    /**
     * Unblock a domain by removing it from hosts file
     */
    void unblockDomain(String domain);
    
    /**
     * Get all blocked domains
     */
    List<BlockedDomain> getBlockedDomains();
    
    /**
     * Check if running with admin privileges
     */
    boolean isAdmin();
    
    /**
     * Synchronize hosts file with database
     */
    void synchronizeHostsFile();
} 