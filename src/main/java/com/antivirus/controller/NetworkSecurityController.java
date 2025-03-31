package com.antivirus.controller;

import com.antivirus.model.NetworkScanResult;
import com.antivirus.service.NetworkSecurityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

/**
 * Controller for handling network security related operations
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

    @Autowired
    private NetworkSecurityService networkSecurityService;

    /**
     * Get current network security status
     */
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getNetworkStatus() {
        return ResponseEntity.ok(networkSecurityService.getNetworkStatus());
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
     * Add domain to block list
     */
    @PostMapping("/domains/block")
    public ResponseEntity<Void> blockDomain(@RequestBody Map<String, String> request) {
        networkSecurityService.blockDomain(request.get("domain"));
        return ResponseEntity.ok().build();
    }

    /**
     * Remove domain from block list
     */
    @DeleteMapping("/domains/{domain}")
    public ResponseEntity<Void> unblockDomain(@PathVariable String domain) {
        networkSecurityService.unblockDomain(domain);
        return ResponseEntity.ok().build();
    }
} 