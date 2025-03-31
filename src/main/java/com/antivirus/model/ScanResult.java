package com.antivirus.model;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import javax.persistence.*;
import java.time.LocalDateTime;

/**
 * Model class representing the result of an antivirus scan
 */
@Data
@Entity
@Table(name = "scan_results")
@Getter
@Setter
public class ScanResult {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String filePath;

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
} 