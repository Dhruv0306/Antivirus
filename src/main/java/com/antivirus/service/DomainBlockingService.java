package com.antivirus.service;

import com.antivirus.model.BlockedDomain;
import java.util.List;

/**
 * Service interface for the blocked-domains database record. As of the H1
 * privilege split, this no longer touches the hosts file at all, that's
 * the privileged system-agent's job now (see
 * docs/plans/h1-privilege-split-plan.md section 6). This interface is
 * intentionally DB-only: persist intent, nothing else.
 */
public interface DomainBlockingService {
    /**
     * Block a domain by recording it as active in the database.
     */
    void blockDomain(String domain, String reason);

    /**
     * Unblock a domain by removing its database record.
     */
    void unblockDomain(String domain);

    /**
     * Get all blocked domains.
     */
    List<BlockedDomain> getBlockedDomains();
}
