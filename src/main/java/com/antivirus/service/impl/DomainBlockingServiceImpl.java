package com.antivirus.service.impl;

import com.antivirus.model.BlockedDomain;
import com.antivirus.repository.BlockedDomainRepository;
import com.antivirus.service.DomainBlockingService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.*;
import java.nio.file.*;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Implementation of DomainBlockingService that uses hosts file for domain blocking
 */
@Service
public class DomainBlockingServiceImpl implements DomainBlockingService {
    private static final Logger logger = LoggerFactory.getLogger(DomainBlockingServiceImpl.class);
    
    private final BlockedDomainRepository blockedDomainRepository;
    private final String hostsFilePath;
    private boolean hostsFileAccessible = false;
    private boolean hasAdminPrivileges = false;
    
    public DomainBlockingServiceImpl(
            BlockedDomainRepository blockedDomainRepository,
            @Value("${system.hosts.file.path:#{systemProperties['os.name'].toLowerCase().contains('win') ? 'C:/Windows/System32/drivers/etc/hosts' : '/etc/hosts'}}") 
            String hostsFilePath) {
        this.blockedDomainRepository = blockedDomainRepository;
        this.hostsFilePath = hostsFilePath;
        
        // First check if we have admin privileges
        hasAdminPrivileges = isAdmin();
        if (!hasAdminPrivileges) {
            logger.warn("Application is not running with administrator privileges. Hosts file modifications will be simulated.");
            return;
        }
        
        // Only try to access the hosts file if we have admin privileges
        try {
            Path hostsPath = Paths.get(hostsFilePath);
            if (Files.exists(hostsPath)) {
                // Try to read the file to check permissions
                Files.readAllLines(hostsPath);
                hostsFileAccessible = true;
                logger.info("Hosts file is accessible at: {}", hostsFilePath);
            } else {
                hostsFileAccessible = false;
                logger.warn("Hosts file does not exist at: {}", hostsFilePath);
            }
        } catch (IOException e) {
            hostsFileAccessible = false;
            logger.warn("Cannot access hosts file at {}: {}", hostsFilePath, e.getMessage());
        }
    }

    @Override
    public boolean isHostsFileAccessible() {
        return hostsFileAccessible && hasAdminPrivileges;
    }

    @Override
    @Transactional
    public void blockDomain(String domain, String reason) {
        if (blockedDomainRepository.existsByDomain(domain)) {
            logger.warn("Domain {} is already blocked", domain);
            return;
        }

        BlockedDomain blockedDomain = new BlockedDomain(domain);
        blockedDomain.setReason(reason);
        blockedDomainRepository.save(blockedDomain);

        // Only try to update hosts file if we have admin privileges
        if (hasAdminPrivileges && hostsFileAccessible) {
            try {
                updateHostsFile();
            } catch (IOException e) {
                logger.error("Failed to update hosts file for domain: " + domain, e);
                // Don't throw exception, just log the error
                // The domain is still blocked in the database
            }
        } else {
            logger.warn("Domain {} will be blocked in database only (no admin privileges or hosts file not accessible)", domain);
        }
    }

    @Override
    @Transactional
    public void unblockDomain(String domain) {
        blockedDomainRepository.findByDomain(domain).ifPresent(blockedDomain -> {
            blockedDomainRepository.delete(blockedDomain);
            // Only try to update hosts file if we have admin privileges
            if (hasAdminPrivileges && hostsFileAccessible) {
                try {
                    updateHostsFile();
                } catch (IOException e) {
                    logger.error("Failed to update hosts file while unblocking domain: " + domain, e);
                    // Don't throw exception, just log the error
                }
            } else {
                logger.warn("Domain {} will be unblocked in database only (no admin privileges or hosts file not accessible)", domain);
            }
        });
    }

    @Override
    public List<BlockedDomain> getBlockedDomains() {
        return blockedDomainRepository.findAll();
    }
    
    @Override
    public boolean isAdmin() {
        // Check if running with admin privileges
        try {
            if (System.getProperty("os.name").toLowerCase().contains("win")) {
                // On Windows, try to write to a protected directory
                Path testPath = Paths.get("C:\\Windows\\Temp\\antivirus_test.tmp");
                Files.write(testPath, "test".getBytes());
                Files.delete(testPath);
                return true;
            } else {
                // On Unix-like systems, check if user is root
                return System.getProperty("user.name").equals("root");
            }
        } catch (Exception e) {
            logger.warn("Not running with administrator privileges: {}", e.getMessage());
            return false;
        }
    }
    
    @Override
    @Scheduled(fixedRate = 300000) // Run every 5 minutes
    public void synchronizeHostsFile() {
        // Only try to sync if we have admin privileges
        if (hasAdminPrivileges && hostsFileAccessible) {
            try {
                updateHostsFile();
            } catch (IOException e) {
                logger.error("Failed to sync blocked domains", e);
            }
        } else {
            logger.debug("Skipping hosts file sync (no admin privileges or file not accessible)");
        }
    }

    private void updateHostsFile() throws IOException {
        List<BlockedDomain> activeBlockedDomains = blockedDomainRepository.findByActiveTrue();
        
        // Read existing hosts file content
        List<String> existingLines = Files.readAllLines(Paths.get(hostsFilePath));
        
        // Filter out our blocked domains (keep system entries)
        List<String> systemEntries = existingLines.stream()
                .filter(line -> !line.contains("# ANTIVIRUS_BLOCKED_DOMAIN"))
                .collect(Collectors.toList());
        
        // Add our blocked domains
        List<String> blockedEntries = activeBlockedDomains.stream()
                .map(domain -> "127.0.0.1 " + domain.getDomain() + " # ANTIVIRUS_BLOCKED_DOMAIN")
                .collect(Collectors.toList());
        
        // Combine system entries with our blocked domains
        systemEntries.addAll(blockedEntries);
        
        // Create backup of existing hosts file
        Path hostsPath = Paths.get(hostsFilePath);
        Path backupPath = Paths.get(hostsFilePath + ".backup");
        
        try {
            // Try to create backup
            Files.copy(hostsPath, backupPath, StandardCopyOption.REPLACE_EXISTING);
            
            // Write updated content to hosts file
            Files.write(hostsPath, systemEntries);
        } catch (AccessDeniedException e) {
            logger.error("Access denied when trying to modify hosts file. Run the application with administrator privileges.", e);
            hostsFileAccessible = false;
            hasAdminPrivileges = false;
            throw e;
        } catch (IOException e) {
            // Restore backup if write fails
            try {
                if (Files.exists(backupPath)) {
                    Files.copy(backupPath, hostsPath, StandardCopyOption.REPLACE_EXISTING);
                }
            } catch (IOException restoreEx) {
                logger.error("Failed to restore hosts file backup", restoreEx);
            }
            throw e;
        }
    }
} 