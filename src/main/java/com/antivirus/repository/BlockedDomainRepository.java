package com.antivirus.repository;

import com.antivirus.model.BlockedDomain;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Repository for BlockedDomain entity
 */
@Repository
public interface BlockedDomainRepository extends JpaRepository<BlockedDomain, Long> {
    /**
     * Check if a domain exists
     */
    boolean existsByDomain(String domain);
    
    /**
     * Find a domain by name
     */
    Optional<BlockedDomain> findByDomain(String domain);
    
    /**
     * Delete a domain by name
     */
    void deleteByDomain(String domain);
    
    /**
     * Find all active blocked domains
     */
    List<BlockedDomain> findByActiveTrue();
} 