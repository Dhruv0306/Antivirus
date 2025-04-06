package com.antivirus.model;

import javax.persistence.*;
import java.time.LocalDateTime;

/**
 * Entity representing a blocked domain
 */
@Entity
@Table(name = "blocked_domains")
public class BlockedDomain {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(unique = true, nullable = false)
    private String domain;
    
    @Column(name = "blocked_at", nullable = false)
    private LocalDateTime blockedAt;
    
    @Column
    private String reason;
    
    @Column(name = "is_active", nullable = false)
    private boolean active = true;
    
    /**
     * Default constructor
     */
    public BlockedDomain() {
        this.blockedAt = LocalDateTime.now();
    }
    
    /**
     * Constructor with domain
     */
    public BlockedDomain(String domain) {
        this();
        this.domain = domain;
    }
    
    // Getters and Setters
    public Long getId() {
        return id;
    }
    
    public void setId(Long id) {
        this.id = id;
    }
    
    public String getDomain() {
        return domain;
    }
    
    public void setDomain(String domain) {
        this.domain = domain;
    }
    
    public LocalDateTime getBlockedAt() {
        return blockedAt;
    }
    
    public void setBlockedAt(LocalDateTime blockedAt) {
        this.blockedAt = blockedAt;
    }
    
    public String getReason() {
        return reason;
    }
    
    public void setReason(String reason) {
        this.reason = reason;
    }
    
    public boolean isActive() {
        return active;
    }
    
    public void setActive(boolean active) {
        this.active = active;
    }
} 