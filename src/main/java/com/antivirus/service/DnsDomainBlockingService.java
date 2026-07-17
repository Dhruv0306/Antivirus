package com.antivirus.service;

import com.antivirus.model.BlockedDomain;
import com.antivirus.repository.BlockedDomainRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.stream.Collectors;

/**
 * Service that handles domain blocking through DNS configuration
 * This provides system-wide blocking without modifying the hosts file
 */
@Service
public class DnsDomainBlockingService {

    private static final Logger logger = LoggerFactory.getLogger(DnsDomainBlockingService.class);

    @Autowired
    private BlockedDomainRepository blockedDomainRepository;

    // H2 Fix: this class's write path (updateDnsConfig/restoreDnsConfig)
    // rewrites a system dnsmasq config file and shells out to
    // `systemctl reload dnsmasq`. It was reachable two ways: never through
    // a live REST endpoint (NetworkSecurityController only reads
    // isDnsConfigAccessible() for status display), but unconditionally
    // every 5 minutes through CompositeDomainBlockingService's
    // @Scheduled(fixedRate = 300000) synchronizeBlockingMethods(), which
    // Spring runs regardless of whether that bean's blockDomain()/
    // unblockDomain() methods are ever called from a controller. On any
    // host where /etc/dnsmasq.d/ happens to be writable (i.e. the process
    // is running with real privileges), this meant a privileged config
    // rewrite + systemctl call fired on a timer with zero user action.
    // Defaulting this to disabled makes the privileged path explicit
    // opt-in (app.domain-blocking.dns.enabled=true) instead of "on by
    // accident whenever the OS permissions happen to allow it".
    @Value("${app.domain-blocking.dns.enabled:false}")
    private boolean dnsBlockingEnabled;

    private static final String DNSMASQ_CONF = "/etc/dnsmasq.d/antivirus-blocked.conf";

    /**
     * Check if dnsmasq config file is accessible
     */
    public boolean isDnsConfigAccessible() {
        try {
            Path dnsmasqConfPath = Paths.get(DNSMASQ_CONF);
            // If file doesn't exist, check if the directory is writable
            if (!Files.exists(dnsmasqConfPath)) {
                Path parentDir = dnsmasqConfPath.getParent();
                return parentDir != null && Files.isWritable(parentDir);
            }
            return Files.isWritable(dnsmasqConfPath);
        } catch (Exception e) {
            logger.warn("dnsmasq config file is not accessible: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Update dnsmasq config with blocked domains
     */
    public void updateDnsConfig() {
        if (!dnsBlockingEnabled) {
            logger.debug("DNS blocking is disabled (app.domain-blocking.dns.enabled=false); skipping dnsmasq update");
            return;
        }

        List<BlockedDomain> domains = blockedDomainRepository.findByActiveTrue();

        // Build dnsmasq address= directives — one per domain
        String content = domains.stream()
                .map(d -> "address=/" + d.getDomain() + "/0.0.0.0")
                .collect(Collectors.joining("\n")) + "\n";

        try {
            Files.writeString(Paths.get(DNSMASQ_CONF), content,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            // Reload dnsmasq without restart
            new ProcessBuilder("systemctl", "reload", "dnsmasq").start().waitFor();
            logger.info("dnsmasq config updated with {} blocked domains", domains.size());
        } catch (IOException | InterruptedException e) {
            logger.error("Failed to update dnsmasq config", e);
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * Restore DNS config (clear the blocklist)
     */
    public void restoreDnsConfig() {
        if (!dnsBlockingEnabled) {
            logger.debug("DNS blocking is disabled (app.domain-blocking.dns.enabled=false); skipping dnsmasq restore");
            return;
        }

        try {
            Path dnsmasqConfPath = Paths.get(DNSMASQ_CONF);
            if (!Files.exists(dnsmasqConfPath)) {
                logger.warn("dnsmasq config not found at {}", DNSMASQ_CONF);
                return;
            }

            // Write empty content to clear blocks safely
            Files.writeString(dnsmasqConfPath, "",
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

            new ProcessBuilder("systemctl", "reload", "dnsmasq").start().waitFor();
            logger.info("dnsmasq config cleared and reloaded");

        } catch (IOException | InterruptedException e) {
            logger.error("Failed to restore dnsmasq config: {}", e.getMessage());
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * Get instructions for configuring system to use DNS blocking
     */
    public Map<String, String> getDnsInstructions() {
        Map<String, String> instructions = new HashMap<>();

        // Linux instructions (most relevant for dnsmasq)
        instructions.put("linux",
                "1. Ensure dnsmasq is installed: sudo apt install dnsmasq\n" +
                        "2. Add 'conf-dir=/etc/dnsmasq.d/,*.conf' to /etc/dnsmasq.conf\n" +
                        "3. Run: sudo systemctl restart dnsmasq\n" +
                        "4. Point system DNS to 127.0.0.1 in /etc/resolv.conf");

        // General instructions for other platforms
        instructions.put("windows",
                "1. DNS blocking via dnsmasq is not natively supported on Windows.\n" +
                        "2. Consider using the Hosts file blocking method instead.");

        instructions.put("macos",
                "1. DNS blocking via dnsmasq requires Homebrew: brew install dnsmasq\n" +
                        "2. Configure as per Linux instructions.");

        return instructions;
    }
}
