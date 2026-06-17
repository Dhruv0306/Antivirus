package com.antivirus.service.impl;

import com.antivirus.model.BlockedDomain;
import com.antivirus.repository.BlockedDomainRepository;
import com.antivirus.service.DomainBlockingService;
import com.antivirus.util.DomainValidator;
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
 * Implementation of DomainBlockingService that uses hosts file for domain
 * blocking
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
            @Value("${system.hosts.file.path:#{systemProperties['os.name'].toLowerCase().contains('win') ? 'C:/Windows/System32/drivers/etc/hosts' : '/etc/hosts'}}") String hostsFilePath) {
        this.blockedDomainRepository = blockedDomainRepository;
        this.hostsFilePath = hostsFilePath;

        Path hostsPath = Paths.get(hostsFilePath);
        hasAdminPrivileges = isAdmin();
        hostsFileAccessible = canModifyHostsFile(hostsPath);

        if (!hostsFileAccessible) {
            logger.warn(
                    "Hosts file at {} is not writable. Domain blocking will be stored in the database only. " +
                            "Run the application as Administrator to enable system-wide hosts blocking.",
                    hostsFilePath);
        } else {
            logger.info("Hosts file is writable at: {}", hostsFilePath);
        }
    }

    private boolean canModifyHostsFile(Path hostsPath) {
        try {
            return Files.exists(hostsPath) && Files.isWritable(hostsPath);
        } catch (Exception e) {
            logger.warn("Cannot verify hosts file write access at {}: {}", hostsPath, e.getMessage());
            return false;
        }
    }

    @Override
    public boolean isHostsFileAccessible() {
        return hostsFileAccessible && hasAdminPrivileges;
    }

    @Override
    @Transactional
    public void blockDomain(String domain, String reason) {
        domain = DomainValidator.validateAndNormalize(domain);
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
            logger.warn("Domain {} will be blocked in database only (no admin privileges or hosts file not accessible)",
                    domain);
        }
    }

    @SuppressWarnings("null")
    @Override
    @Transactional
    public void unblockDomain(String domain) {
        final String normalizedDomain = DomainValidator.validateAndNormalize(domain);
        blockedDomainRepository.findByDomain(normalizedDomain).ifPresent(blockedDomain -> {
            blockedDomainRepository.delete(blockedDomain);
            // Only try to update hosts file if we have admin privileges
            if (hasAdminPrivileges && hostsFileAccessible) {
                try {
                    updateHostsFile();
                } catch (IOException e) {
                    logger.error("Failed to update hosts file while unblocking domain: " + normalizedDomain, e);
                    // Don't throw exception, just log the error
                }
            } else {
                logger.warn(
                        "Domain {} will be unblocked in database only (no admin privileges or hosts file not accessible)",
                        normalizedDomain);
            }
        });
    }

    @Override
    public List<BlockedDomain> getBlockedDomains() {
        return blockedDomainRepository.findAll();
    }

    @Override
    public boolean isAdmin() {
        return canModifyHostsFile(Paths.get(hostsFilePath));
    }

    /**
     * Explicitly re-check filesystem permissions and update cached fields.
     * Call this only when a deliberate privilege state change is needed
     * (e.g. after runtime privilege escalation).
     */
    public void refreshPrivilegeCheck() {
        this.hasAdminPrivileges = canModifyHostsFile(Paths.get(hostsFilePath));
        this.hostsFileAccessible = hasAdminPrivileges;
    }

    @Override
    @Scheduled(fixedRate = 300000) // Run every 5 minutes
    public void synchronizeHostsFile() {
        // Only try to sync if we have admin privileges
        if (hasAdminPrivileges && hostsFileAccessible) {
            try {
                updateHostsFile();
            } catch (AccessDeniedException e) {
                hostsFileAccessible = false;
                hasAdminPrivileges = false;
                logger.warn("Hosts file sync skipped: write access denied. Using database-only blocking.");
            } catch (IOException e) {
                logger.warn("Failed to sync blocked domains: {}", e.getMessage());
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
            logger.warn("Access denied when modifying hosts file. Using database-only blocking.");
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