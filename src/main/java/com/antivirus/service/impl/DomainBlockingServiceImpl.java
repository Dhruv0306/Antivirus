package com.antivirus.service.impl;

import com.antivirus.model.BlockedDomain;
import com.antivirus.repository.BlockedDomainRepository;
import com.antivirus.service.DomainBlockingService;
import com.antivirus.util.DomainValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * DB-only now. As of the H1 privilege split (see
 * docs/plans/h1-privilege-split-plan.md section 6), this class no longer
 * touches the hosts file, checks admin privileges, or runs a scheduled
 * sync, all of that moved to the privileged system-agent process, which
 * polls the same blocked_domains table this class writes to. This class's
 * entire job now is: validate, persist intent, nothing else.
 */
@Service
public class DomainBlockingServiceImpl implements DomainBlockingService {
    private static final Logger logger = LoggerFactory.getLogger(DomainBlockingServiceImpl.class);

    private final BlockedDomainRepository blockedDomainRepository;

    public DomainBlockingServiceImpl(BlockedDomainRepository blockedDomainRepository) {
        this.blockedDomainRepository = blockedDomainRepository;
    }

    @Override
    @Transactional
    public void blockDomain(String domain, String reason) {
        domain = DomainValidator.validateAndNormalize(domain);
        if (blockedDomainRepository.existsByDomain(domain)) {
            logger.warn("Domain {} is already blocked", domain);
            return;
        }

        BlockedDomain blockedDomain = new BlockedDomain(domain);
        blockedDomain.setReason(reason);
        blockedDomainRepository.save(blockedDomain);
        logger.info("Domain {} recorded as blocked; the system-agent will enforce it on its next poll", domain);
    }

    @Override
    @Transactional
    public void unblockDomain(String domain) {
        final String normalizedDomain = DomainValidator.validateAndNormalize(domain);
        blockedDomainRepository.findByDomain(normalizedDomain).ifPresent(blockedDomain -> {
            blockedDomainRepository.delete(blockedDomain);
            logger.info("Domain {} removed; the system-agent will stop enforcing it on its next poll", normalizedDomain);
        });
    }

    @Override
    public List<BlockedDomain> getBlockedDomains() {
        return blockedDomainRepository.findAll();
    }
}
