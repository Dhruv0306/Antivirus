package com.antivirus.service.impl;

import com.antivirus.model.BlockedDomain;
import com.antivirus.repository.BlockedDomainRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * As of the H1 privilege split (see
 * docs/plans/h1-privilege-split-plan.md section 6),
 * DomainBlockingServiceImpl is DB-only, no hosts file, no admin-privilege
 * checks, no scheduled sync. This test file didn't exist before this PR
 * either way, filling that gap now that the class is small enough to be
 * fully covered without needing filesystem mocking.
 */
@ExtendWith(MockitoExtension.class)
class DomainBlockingServiceImplTest {

    @Mock
    private BlockedDomainRepository blockedDomainRepository;

    @InjectMocks
    private DomainBlockingServiceImpl domainBlockingService;

    @Test
    void blockDomain_ShouldPersistNewDomain() {
        when(blockedDomainRepository.existsByDomain("malicious.example.com")).thenReturn(false);

        domainBlockingService.blockDomain("malicious.example.com", "Known malware host");

        verify(blockedDomainRepository).save(argThat(saved ->
                saved.getDomain().equals("malicious.example.com")
                        && "Known malware host".equals(saved.getReason())));
    }

    @Test
    void blockDomain_ShouldNormalizeDomainBeforePersisting() {
        when(blockedDomainRepository.existsByDomain("malicious.example.com")).thenReturn(false);

        domainBlockingService.blockDomain("MALICIOUS.EXAMPLE.COM", null);

        verify(blockedDomainRepository).save(argThat(saved -> saved.getDomain().equals("malicious.example.com")));
    }

    @Test
    void blockDomain_ShouldNotDuplicateAnAlreadyBlockedDomain() {
        when(blockedDomainRepository.existsByDomain("malicious.example.com")).thenReturn(true);

        domainBlockingService.blockDomain("malicious.example.com", "reason");

        verify(blockedDomainRepository, never()).save(any(BlockedDomain.class));
    }

    @Test
    void blockDomain_ShouldRejectAnInvalidDomain() {
        assertThrows(IllegalArgumentException.class,
                () -> domainBlockingService.blockDomain("not a valid domain", "reason"));
        verify(blockedDomainRepository, never()).save(any(BlockedDomain.class));
    }

    @Test
    void unblockDomain_ShouldDeleteAnExistingDomain() {
        BlockedDomain existing = new BlockedDomain("malicious.example.com");
        when(blockedDomainRepository.findByDomain("malicious.example.com")).thenReturn(Optional.of(existing));

        domainBlockingService.unblockDomain("malicious.example.com");

        verify(blockedDomainRepository).delete(existing);
    }

    @Test
    void unblockDomain_ShouldBeANoOpWhenDomainDoesNotExist() {
        when(blockedDomainRepository.findByDomain("not-blocked.example.com")).thenReturn(Optional.empty());

        domainBlockingService.unblockDomain("not-blocked.example.com");

        verify(blockedDomainRepository, never()).delete(any(BlockedDomain.class));
    }

    @Test
    void unblockDomain_ShouldRejectAnInvalidDomain() {
        assertThrows(IllegalArgumentException.class,
                () -> domainBlockingService.unblockDomain(""));
        verifyNoInteractions(blockedDomainRepository);
    }

    @Test
    void getBlockedDomains_ShouldReturnEveryRecordFromTheRepository() {
        BlockedDomain d1 = new BlockedDomain("first.example.com");
        BlockedDomain d2 = new BlockedDomain("second.example.com");
        when(blockedDomainRepository.findAll()).thenReturn(List.of(d1, d2));

        List<BlockedDomain> result = domainBlockingService.getBlockedDomains();

        assertEquals(2, result.size());
        assertTrue(result.contains(d1));
        assertTrue(result.contains(d2));
    }
}
