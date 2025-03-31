package com.antivirus.model;

import lombok.Data;
import java.time.LocalDateTime;
import java.util.List;

/**
 * Model class representing the result of a network security scan
 */
@Data
public class NetworkScanResult {
    private int threats;
    private List<NetworkVulnerability> vulnerabilities;
    private LocalDateTime scanTime;
    private String status;
    private List<String> openPorts;
    private List<String> suspiciousConnections;
    private boolean firewallEnabled;
    private boolean webProtectionEnabled;
} 