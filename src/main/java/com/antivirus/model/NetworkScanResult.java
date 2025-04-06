package com.antivirus.model;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.util.List;

/**
 * Model class representing the result of a network security scan
 */
@Entity
@Table(name = "network_scan_results")
public class NetworkScanResult {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private int threats;
    
    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JoinColumn(name = "scan_result_id")
    private List<NetworkVulnerability> vulnerabilities;
    
    private LocalDateTime scanTime;
    private String status;
    
    @ElementCollection
    @CollectionTable(name = "open_ports", joinColumns = @JoinColumn(name = "scan_result_id"))
    @Column(name = "port")
    private List<String> openPorts;
    
    @ElementCollection
    @CollectionTable(name = "suspicious_connections", joinColumns = @JoinColumn(name = "scan_result_id"))
    @Column(name = "connection")
    private List<String> suspiciousConnections;
    
    private boolean firewallEnabled;
    private boolean webProtectionEnabled;
    
    // New fields for tracking active threats and blocked attempts
    private int activeThreats;
    private int blockedAttempts;
    
    // Getters and Setters
    public Long getId() {
        return id;
    }
    
    public void setId(Long id) {
        this.id = id;
    }
    
    public int getThreats() {
        return threats;
    }
    
    public void setThreats(int threats) {
        this.threats = threats;
    }
    
    public List<NetworkVulnerability> getVulnerabilities() {
        return vulnerabilities;
    }
    
    public void setVulnerabilities(List<NetworkVulnerability> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }
    
    public LocalDateTime getScanTime() {
        return scanTime;
    }
    
    public void setScanTime(LocalDateTime scanTime) {
        this.scanTime = scanTime;
    }
    
    public String getStatus() {
        return status;
    }
    
    public void setStatus(String status) {
        this.status = status;
    }
    
    public List<String> getOpenPorts() {
        return openPorts;
    }
    
    public void setOpenPorts(List<String> openPorts) {
        this.openPorts = openPorts;
    }
    
    public List<String> getSuspiciousConnections() {
        return suspiciousConnections;
    }
    
    public void setSuspiciousConnections(List<String> suspiciousConnections) {
        this.suspiciousConnections = suspiciousConnections;
    }
    
    public boolean isFirewallEnabled() {
        return firewallEnabled;
    }
    
    public void setFirewallEnabled(boolean firewallEnabled) {
        this.firewallEnabled = firewallEnabled;
    }
    
    public boolean isWebProtectionEnabled() {
        return webProtectionEnabled;
    }
    
    public void setWebProtectionEnabled(boolean webProtectionEnabled) {
        this.webProtectionEnabled = webProtectionEnabled;
    }
    
    // New getters and setters for active threats and blocked attempts
    public int getActiveThreats() {
        return activeThreats;
    }
    
    public void setActiveThreats(int activeThreats) {
        this.activeThreats = activeThreats;
    }
    
    public int getBlockedAttempts() {
        return blockedAttempts;
    }
    
    public void setBlockedAttempts(int blockedAttempts) {
        this.blockedAttempts = blockedAttempts;
    }
} 