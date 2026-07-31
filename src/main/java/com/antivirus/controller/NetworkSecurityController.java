package com.antivirus.controller;

import com.antivirus.model.AgentStatus;
import com.antivirus.model.BlockedDomain;
import com.antivirus.model.NetworkScanResult;
import com.antivirus.repository.AgentStatusRepository;
import com.antivirus.service.NetworkSecurityService;
import com.antivirus.service.DomainBlockingService;
import com.antivirus.service.ProxyDomainBlockingService;
import com.antivirus.util.DomainValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Controller for managing network security features.
 *
 * As of the H1 privilege split (see
 * docs/plans/h1-privilege-split-plan.md section 6), this controller no
 * longer probes the filesystem or checks admin privileges directly, that
 * logic (and the ability to actually write /etc/hosts or
 * /etc/dnsmasq.d) belongs entirely to the privileged system-agent
 * process now. Everything here reads {@code agent_status}, a row only
 * the agent ever writes, to answer "can blocking actually be enforced
 * right now".
 */
@RestController
@RequestMapping("/api/network-security")
public class NetworkSecurityController {

    private static final Logger logger = LoggerFactory.getLogger(NetworkSecurityController.class);

    /**
     * Singleton row id for agent_status (see V5__add_agent_status.sql).
     */
    private static final Long AGENT_STATUS_ID = 1L;

    /**
     * If the agent hasn't reported a heartbeat within this window, treat
     * it as unreachable rather than trusting a possibly-stale
     * hosts_file_writable/dns_config_writable value. 90s is 3x the
     * agent's default 30s poll interval (see system-agent's AgentConfig).
     */
    private static final long AGENT_STALE_THRESHOLD_SECONDS = 90;

    @Autowired
    private NetworkSecurityService networkSecurityService;

    @Autowired
    private DomainBlockingService domainBlockingService;

    @Autowired
    private ProxyDomainBlockingService proxyDomainBlockingService;

    @Autowired
    private AgentStatusRepository agentStatusRepository;

    /**
     * Reads the current agent_status row and applies the staleness check.
     * Never null: if the row is missing entirely (e.g. a freshly migrated
     * environment the agent hasn't started against yet) or the heartbeat
     * is stale, every capability reads as false and agentReachable is
     * false, fail closed rather than trusting an absent or old value.
     */
    private AgentSnapshot readAgentSnapshot() {
        Optional<AgentStatus> status = agentStatusRepository.findById(AGENT_STATUS_ID);
        if (status.isEmpty()) {
            return new AgentSnapshot(false, false, false);
        }

        AgentStatus agentStatus = status.get();
        LocalDateTime lastHeartbeat = agentStatus.getLastHeartbeatAt();
        boolean reachable = lastHeartbeat != null
                && Duration.between(lastHeartbeat, LocalDateTime.now()).getSeconds() <= AGENT_STALE_THRESHOLD_SECONDS;

        if (!reachable) {
            return new AgentSnapshot(false, false, false);
        }

        return new AgentSnapshot(true, agentStatus.isHostsFileWritable(), agentStatus.isDnsConfigWritable());
    }

    private record AgentSnapshot(boolean agentReachable, boolean hostsFileWritable, boolean dnsConfigWritable) {
    }

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
            List<BlockedDomain> domains = domainBlockingService.getBlockedDomains();
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

        // Agent-derived status, sourced from agent_status, not a direct
        // filesystem probe, the web app never touches those paths anymore.
        AgentSnapshot agent = readAgentSnapshot();
        response.put("agentReachable", agent.agentReachable());
        response.put("hostsFileAccessible", agent.hostsFileWritable());
        response.put("hasAdminPrivileges", agent.hostsFileWritable());

        // Check proxy server status (unchanged, needs no privilege, stays in the web app)
        boolean proxyRunning = proxyDomainBlockingService.isProxyRunning();
        response.put("proxyServerRunning", proxyRunning);
        if (proxyRunning) {
            response.put("proxyPort", proxyDomainBlockingService.getProxyPort());
        }

        response.put("dnsConfigAccessible", agent.dnsConfigWritable());

        if (!agent.agentReachable()) {
            response.put("warning", "The system-agent is unreachable (no heartbeat within the last "
                    + AGENT_STALE_THRESHOLD_SECONDS + "s). Domain blocking will be recorded in the database only "
                    + "until the agent resumes syncing. Consider using the proxy server method in the meantime.");
        } else if (!agent.hostsFileWritable()) {
            response.put("warning", "The system-agent does not currently have write access to the hosts file. "
                    + "Domain blocking will be recorded in the database only. "
                    + "Consider using the proxy server or DNS blocking methods instead.");
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
        Map<String, Object> response = new HashMap<>();

        try {
            String domain = DomainValidator.validateAndNormalize(request.get("domain"));
            String reason = request.get("reason");
            domainBlockingService.blockDomain(domain, reason);
            response.put("success", true);
            response.put("message", "Domain blocked successfully");

            AgentSnapshot agent = readAgentSnapshot();
            if (!agent.agentReachable() || !agent.hostsFileWritable()) {
                response.put("warning", "Domain recorded in the database. System-wide enforcement depends on the "
                        + "system-agent, which is currently " + (agent.agentReachable() ? "reachable but without "
                        + "hosts file write access" : "unreachable")
                        + ". Consider using the proxy server method for immediate enforcement.");
            }

            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            response.put("success", false);
            response.put("error", "Invalid domain name");
            return ResponseEntity.badRequest().body(response);
        } catch (Exception e) {
            logger.error("Failed to block domain", e);
            response.put("success", false);
            response.put("error", "Failed to block domain");
            return ResponseEntity.badRequest().body(response);
        }
    }

    /**
     * Unblock a domain
     */
    @PostMapping("/unblock")
    public ResponseEntity<Map<String, Object>> unblockDomain(@RequestBody Map<String, String> request) {
        Map<String, Object> response = new HashMap<>();

        try {
            String domain = DomainValidator.validateAndNormalize(request.get("domain"));
            domainBlockingService.unblockDomain(domain);
            response.put("success", true);
            response.put("message", "Domain unblocked successfully");

            AgentSnapshot agent = readAgentSnapshot();
            if (!agent.agentReachable() || !agent.hostsFileWritable()) {
                response.put("warning", "Domain removed from the database. System-wide removal depends on the "
                        + "system-agent, which is currently " + (agent.agentReachable() ? "reachable but without "
                        + "hosts file write access" : "unreachable") + ".");
            }

            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            response.put("success", false);
            response.put("error", "Invalid domain name");
            return ResponseEntity.badRequest().body(response);
        } catch (Exception e) {
            logger.error("Failed to unblock domain", e);
            response.put("success", false);
            response.put("error", "Failed to unblock domain");
            return ResponseEntity.badRequest().body(response);
        }
    }

    /**
     * Get list of blocked domains
     */
    @GetMapping("/blocked")
    public ResponseEntity<List<BlockedDomain>> getBlockedDomains() {
        return ResponseEntity.ok(domainBlockingService.getBlockedDomains());
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
            logger.error("Failed to start proxy server", e);
            response.put("success", false);
            response.put("error", "Failed to start proxy server");
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
            logger.error("Failed to stop proxy server", e);
            response.put("success", false);
            response.put("error", "Failed to stop proxy server");
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
     * DNS blocking status/trigger endpoint.
     *
     * As of the H1 privilege split, the web app has no DNS-write code
     * path at all, the system-agent polls and applies blocked_domains
     * autonomously, there's nothing left for this endpoint to trigger.
     * Kept (rather than removed) since nothing in the frontend currently
     * calls it but removing a REST endpoint is a bigger contract change
     * than repurposing one; it now reports current agent-derived status
     * instead of performing a synchronous write.
     */
    @PostMapping("/dns/update")
    public ResponseEntity<Map<String, Object>> updateDnsConfig() {
        Map<String, Object> response = new HashMap<>();

        AgentSnapshot agent = readAgentSnapshot();
        response.put("success", true);
        response.put("message", "DNS blocking is applied automatically by the system-agent; "
                + "there is no manual trigger from the web app anymore.");
        response.put("agentReachable", agent.agentReachable());
        response.put("dnsConfigAccessible", agent.dnsConfigWritable());

        return ResponseEntity.ok(response);
    }

    /**
     * Get alternative domain blocking methods
     */
    @GetMapping("/blocking-methods")
    public ResponseEntity<Map<String, Object>> getAlternativeDomainBlockingMethods() {
        Map<String, Object> response = new HashMap<>();

        AgentSnapshot agent = readAgentSnapshot();
        boolean proxyRunning = proxyDomainBlockingService.isProxyRunning();

        response.put("hostsFileMethod", Map.of(
                "available", agent.agentReachable() && agent.hostsFileWritable(),
                "requiresAdmin", true,
                "description", "The system-agent modifies the hosts file to redirect blocked domains to localhost"));

        response.put("proxyMethod", Map.of(
                "available", true,
                "running", proxyRunning,
                "port", proxyDomainBlockingService.getProxyPort(),
                "description", "Uses a local proxy server to block access to malicious domains"));

        response.put("dnsMethod", Map.of(
                "available", agent.agentReachable() && agent.dnsConfigWritable(),
                "requiresAdmin", true,
                "description", "The system-agent configures DNS settings to block access to malicious domains"));

        if (!agent.agentReachable()) {
            response.put("recommendation", "The system-agent is currently unreachable, so hosts file and DNS "
                    + "blocking cannot be enforced system-wide. We recommend using the proxy server method, "
                    + "which runs in the web app itself and doesn't depend on the agent.");
        } else if (!agent.hostsFileWritable()) {
            response.put("recommendation", "Since hosts file modification is not currently available, "
                    + "we recommend using the proxy server method which doesn't require administrator privileges.");
        }

        return ResponseEntity.ok(response);
    }
}
