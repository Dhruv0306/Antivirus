package com.antivirus.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Model class representing the result of an antivirus scan
 */
@Entity
@Table(name = "scan_results")
public class ScanResult {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String filePath;

    @Transient
    private String fileName;

    @Column(name = "owner_username")
    private String ownerUsername;

    @Column(nullable = false)
    private String threatType; // VIRUS, MALWARE, TROJAN, RANSOMWARE, KEYLOGGER

    @Column(nullable = false)
    private boolean infected;

    @Column
    private String threatDetails;

    @Column(nullable = false)
    private LocalDateTime scanDateTime;

    @Column(nullable = false)
    private String scanType; // FILE, DIRECTORY, SYSTEM

    @Column
    private String actionTaken; // QUARANTINED, DELETED, CLEANED

    @PrePersist
    protected void onCreate() {
        scanDateTime = LocalDateTime.now();
    }
    
    // Getters and Setters
    public Long getId() {
        return id;
    }
    
    public void setId(Long id) {
        this.id = id;
    }
    
    @JsonIgnore
    public String getFilePath() {
        return filePath;
    }
    
    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public String getFileName() {
        if (fileName != null && !fileName.isBlank()) {
            return fileName;
        }
        if (filePath == null || filePath.isBlank()) {
            return null;
        }

        try {
            Path path = Paths.get(filePath);
            Path name = path.getFileName();
            return name != null ? name.toString() : filePath;
        } catch (Exception e) {
            return filePath;
        }
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    @JsonIgnore
    public String getOwnerUsername() {
        return ownerUsername;
    }

    public void setOwnerUsername(String ownerUsername) {
        this.ownerUsername = ownerUsername;
    }
    
    public String getThreatType() {
        return threatType;
    }
    
    public void setThreatType(String threatType) {
        this.threatType = threatType;
    }
    
    public boolean isInfected() {
        return infected;
    }
    
    public void setInfected(boolean infected) {
        this.infected = infected;
    }
    
    public String getThreatDetails() {
        return threatDetails;
    }
    
    public void setThreatDetails(String threatDetails) {
        this.threatDetails = threatDetails;
    }
    
    public LocalDateTime getScanDateTime() {
        return scanDateTime;
    }
    
    public void setScanDateTime(LocalDateTime scanDateTime) {
        this.scanDateTime = scanDateTime;
    }
    
    public String getScanType() {
        return scanType;
    }
    
    public void setScanType(String scanType) {
        this.scanType = scanType;
    }
    
    public String getActionTaken() {
        return actionTaken;
    }
    
    public void setActionTaken(String actionTaken) {
        this.actionTaken = actionTaken;
    }
}
