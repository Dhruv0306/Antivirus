package com.antivirus.service;

import com.antivirus.model.BlockedDomain;
import com.antivirus.repository.BlockedDomainRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Method;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

/**
 * Regression coverage for the SSRF fix (N-03): the proxy must refuse to
 * relay requests to loopback, private, and link-local addresses, and must
 * correctly consult the blocked-domain list before forwarding traffic.
 */
@ExtendWith(MockitoExtension.class)
class ProxyDomainBlockingServiceTest {

    @Mock
    private BlockedDomainRepository blockedDomainRepository;

    @InjectMocks
    private ProxyDomainBlockingService proxyDomainBlockingService;

    private Method isPrivateOrLoopbackMethod;

    @BeforeEach
    void setUp() throws NoSuchMethodException {
        isPrivateOrLoopbackMethod = ProxyDomainBlockingService.class
                .getDeclaredMethod("isPrivateOrLoopback", String.class);
        isPrivateOrLoopbackMethod.setAccessible(true);
    }

    private boolean isPrivateOrLoopback(String host) throws Exception {
        return (boolean) isPrivateOrLoopbackMethod.invoke(proxyDomainBlockingService, host);
    }

    // ── isDomainBlocked ──────────────────────────────────────────────

    @Test
    void isDomainBlocked_ShouldReturnTrueWhenDomainIsActivelyBlocked() {
        BlockedDomain blocked = new BlockedDomain("malicious-site.com");
        when(blockedDomainRepository.findByDomain("malicious-site.com")).thenReturn(Optional.of(blocked));

        assertTrue(proxyDomainBlockingService.isDomainBlocked("malicious-site.com"));
    }

    @Test
    void isDomainBlocked_ShouldReturnFalseWhenDomainRecordIsInactive() {
        BlockedDomain inactive = new BlockedDomain("formerly-blocked.com");
        inactive.setActive(false);
        when(blockedDomainRepository.findByDomain("formerly-blocked.com")).thenReturn(Optional.of(inactive));

        assertFalse(proxyDomainBlockingService.isDomainBlocked("formerly-blocked.com"));
    }

    @Test
    void isDomainBlocked_ShouldReturnFalseWhenDomainNotFound() {
        when(blockedDomainRepository.findByDomain("safe-site.com")).thenReturn(Optional.empty());

        assertFalse(proxyDomainBlockingService.isDomainBlocked("safe-site.com"));
    }

    @Test
    void isDomainBlocked_ShouldReturnFalseForNullOrBlankDomain() {
        assertFalse(proxyDomainBlockingService.isDomainBlocked(null));
        assertFalse(proxyDomainBlockingService.isDomainBlocked("   "));
    }

    @Test
    void isDomainBlocked_ShouldNormalizeToLowercaseAndStripPort() {
        when(blockedDomainRepository.findByDomain("malicious-site.com"))
                .thenReturn(Optional.of(new BlockedDomain("malicious-site.com")));

        assertTrue(proxyDomainBlockingService.isDomainBlocked("Malicious-Site.COM:8443"));
    }

    // ── isPrivateOrLoopback (SSRF regression guard) ─────────────────

    @ParameterizedTest
    @ValueSource(strings = {
            "localhost",
            "127.0.0.1",
            "10.0.0.5",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.1.1"
    })
    void isPrivateOrLoopback_ShouldBlockLoopbackAndPrivateAddresses(String host) throws Exception {
        assertTrue(isPrivateOrLoopback(host), host + " should be treated as private/loopback");
    }

    @Test
    void isPrivateOrLoopback_ShouldAllowPublicIpAddress() throws Exception {
        // 8.8.8.8 (a well-known public DNS resolver) must not be blocked
        assertFalse(isPrivateOrLoopback("8.8.8.8"));
    }

    @Test
    void isPrivateOrLoopback_ShouldBlockUnresolvableHostFailClosed() throws Exception {
        assertTrue(isPrivateOrLoopback("this-host-does-not-exist.invalid"));
    }

    // ── proxy lifecycle accessors ────────────────────────────────────

    @Test
    void isProxyRunning_ShouldReturnFalseBeforeStart() {
        assertFalse(proxyDomainBlockingService.isProxyRunning());
    }

    @Test
    void getProxyInstructions_ShouldReturnInstructionsForAllPlatforms() {
        var instructions = proxyDomainBlockingService.getProxyInstructions();

        assertTrue(instructions.containsKey("windows"));
        assertTrue(instructions.containsKey("macos"));
        assertTrue(instructions.containsKey("linux"));
    }
}
