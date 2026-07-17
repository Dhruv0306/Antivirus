package com.antivirus.service;

import com.antivirus.repository.BlockedDomainRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * H2 fix: updateDnsConfig()/restoreDnsConfig() rewrite a system dnsmasq
 * config file and shell out to `systemctl reload dnsmasq`. This ran
 * unconditionally every 5 minutes via CompositeDomainBlockingService's
 * @Scheduled sync, regardless of whether anyone used the DNS-blocking
 * feature through a controller. app.domain-blocking.dns.enabled now gates
 * both methods, defaulting to false, so the privileged path is explicit
 * opt-in instead of "on whenever OS permissions happen to allow it".
 */
@ExtendWith(MockitoExtension.class)
class DnsDomainBlockingServiceTest {

    @Mock
    private BlockedDomainRepository blockedDomainRepository;

    @InjectMocks
    private DnsDomainBlockingService dnsDomainBlockingService;

    @Test
    void updateDnsConfig_ShouldNoOpWhenDisabled() {
        // dnsBlockingEnabled defaults to false (no @Value injection under
        // plain Mockito), matching the field's declared default.
        dnsDomainBlockingService.updateDnsConfig();

        verify(blockedDomainRepository, never()).findByActiveTrue();
    }

    @Test
    void restoreDnsConfig_ShouldNoOpWhenDisabled() {
        // restoreDnsConfig() doesn't touch the repository either way, but
        // it should return immediately without attempting any filesystem
        // or process work when disabled. Absence of an exception here
        // (no /etc/dnsmasq.d/ access in a test environment) is the
        // observable signal that the early-return guard fired.
        dnsDomainBlockingService.restoreDnsConfig();
    }

    @Test
    void updateDnsConfig_ShouldAttemptUpdateWhenExplicitlyEnabled() {
        ReflectionTestUtils.setField(dnsDomainBlockingService, "dnsBlockingEnabled", true);
        when(blockedDomainRepository.findByActiveTrue()).thenReturn(java.util.List.of());

        // In this sandboxed test environment /etc/dnsmasq.d/ won't be
        // writable, so the write itself fails and is caught/logged inside
        // updateDnsConfig() rather than thrown. What this test confirms is
        // that enabling the flag actually reaches the repository call,
        // proving the guard is the thing gating behavior, not some other
        // accidental short-circuit.
        dnsDomainBlockingService.updateDnsConfig();

        verify(blockedDomainRepository).findByActiveTrue();
    }
}
