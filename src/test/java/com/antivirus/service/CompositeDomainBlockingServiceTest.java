package com.antivirus.service;

import com.antivirus.model.BlockedDomain;
import com.antivirus.repository.BlockedDomainRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Covers the validation gap fix: blockDomain() used to save straight to the
 * database with no validation, unlike DomainBlockingServiceImpl's
 * blockDomain(),
 * which does call DomainValidator.validateAndNormalize(). An unvalidated
 * domain reaching persistence would flow into
 * DnsDomainBlockingService.updateDnsConfig(), which writes it verbatim into
 * a dnsmasq config file, a config-injection path via a newline or other
 * control character in the domain string.
 */
@ExtendWith(MockitoExtension.class)
class CompositeDomainBlockingServiceTest {

    @Mock
    private DomainBlockingService hostsBlockingService;

    @Mock
    private ProxyDomainBlockingService proxyBlockingService;

    @Mock
    private DnsDomainBlockingService dnsBlockingService;

    @Mock
    private BlockedDomainRepository blockedDomainRepository;

    @InjectMocks
    private CompositeDomainBlockingService compositeDomainBlockingService;

    @Test
    void blockDomain_ShouldRejectInvalidDomainWithoutPersistingAnything() {
        // A newline is exactly the kind of character that would corrupt a
        // dnsmasq config file if it ever reached updateDnsConfig() unvalidated.
        String maliciousDomain = "evil.com\naddress=/attacker-controlled.example/1.2.3.4";

        assertThrows(IllegalArgumentException.class,
                () -> compositeDomainBlockingService.blockDomain(maliciousDomain, "test"));

        verify(blockedDomainRepository, never()).save(any(BlockedDomain.class));
        verifyNoInteractions(hostsBlockingService);
        verifyNoInteractions(dnsBlockingService);
    }

    @Test
    void blockDomain_ShouldPersistNormalizedDomainForValidInput() {
        lenient().when(hostsBlockingService.isHostsFileAccessible()).thenReturn(false);
        lenient().when(dnsBlockingService.isDnsConfigAccessible()).thenReturn(false);

        compositeDomainBlockingService.blockDomain("  EXAMPLE.COM  ", "malware distribution");

        ArgumentCaptor<BlockedDomain> captor = ArgumentCaptor.forClass(BlockedDomain.class);
        verify(blockedDomainRepository, times(1)).save(captor.capture());
        assertEquals("example.com", captor.getValue().getDomain());
        assertEquals("malware distribution", captor.getValue().getReason());
    }

    @Test
    void blockDomain_ShouldUseNormalizedDomainWhenNotifyingHostsFileService() {
        when(hostsBlockingService.isHostsFileAccessible()).thenReturn(true);
        lenient().when(dnsBlockingService.isDnsConfigAccessible()).thenReturn(false);

        compositeDomainBlockingService.blockDomain("  EXAMPLE.COM  ", "test");

        verify(hostsBlockingService, times(1)).blockDomain("example.com", "test");
    }
}