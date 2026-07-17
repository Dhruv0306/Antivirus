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

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.ByteArrayInputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

/**
 * Regression coverage for the SSRF fix (N-03): the proxy must refuse to
 * relay requests to loopback, private, and link-local addresses, and must
 * correctly consult the blocked-domain list before forwarding traffic.
 *
 * Also covers the B-02 hardening pass: the DNS-rebinding TOCTOU fix
 * (resolveAndValidate) and the buffered-request-body-loss fix
 * (flushBufferedBytes).
 */
@ExtendWith(MockitoExtension.class)
class ProxyDomainBlockingServiceTest {

    @Mock
    private BlockedDomainRepository blockedDomainRepository;

    @InjectMocks
    private ProxyDomainBlockingService proxyDomainBlockingService;

    private Method isPrivateOrLoopbackMethod;
    private Method resolveAndValidateMethod;
    private Method flushBufferedBytesMethod;
    private Method readHeadersMethod;

    @BeforeEach
    void setUp() throws NoSuchMethodException {
        isPrivateOrLoopbackMethod = ProxyDomainBlockingService.class
                .getDeclaredMethod("isPrivateOrLoopback", String.class);
        isPrivateOrLoopbackMethod.setAccessible(true);

        resolveAndValidateMethod = ProxyDomainBlockingService.class
                .getDeclaredMethod("resolveAndValidate", String.class);
        resolveAndValidateMethod.setAccessible(true);

        flushBufferedBytesMethod = ProxyDomainBlockingService.class
                .getDeclaredMethod("flushBufferedBytes", BufferedReader.class, OutputStream.class);
        flushBufferedBytesMethod.setAccessible(true);

        readHeadersMethod = ProxyDomainBlockingService.class
                .getDeclaredMethod("readHeaders", BufferedReader.class);
        readHeadersMethod.setAccessible(true);
    }

    private boolean isPrivateOrLoopback(String host) throws Exception {
        return (boolean) isPrivateOrLoopbackMethod.invoke(proxyDomainBlockingService, host);
    }

    // Unwraps InvocationTargetException so callers can assertThrows the
    // real exception type (SecurityException) rather than its reflection
    // wrapper.
    private InetAddress resolveAndValidate(String host) throws Throwable {
        try {
            return (InetAddress) resolveAndValidateMethod.invoke(proxyDomainBlockingService, host);
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }

    private void flushBufferedBytes(BufferedReader reader, OutputStream out) throws Throwable {
        try {
            flushBufferedBytesMethod.invoke(proxyDomainBlockingService, reader, out);
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }

    @SuppressWarnings("unchecked")
    private List<String> readHeaders(BufferedReader reader) throws Throwable {
        try {
            return (List<String>) readHeadersMethod.invoke(proxyDomainBlockingService, reader);
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
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

    @Test
    void isPrivateOrLoopback_ShouldBlockLocalhostSubdomains() throws Exception {
        // RFC 6761 reserves the entire .localhost TLD to resolve to loopback
        assertTrue(isPrivateOrLoopback("anything.localhost"));
    }

    // ── C1 fix: IPv4-mapped IPv6 addresses must not bypass the SSRF guard ──
    //
    // Inet6Address.isLinkLocalAddress()/isSiteLocalAddress() check the
    // fe80::/10 and fec0::/10 prefixes against the raw 16 address bytes,
    // which an IPv4-mapped address (::ffff:a.b.c.d) never matches even when
    // the IPv4 value it carries is itself loopback, link-local, or private.
    // Before the fix, a DNS response (or literal) resolving to one of these
    // let an attacker reach loopback/private/metadata addresses through the
    // proxy despite this check passing.
    @ParameterizedTest
    @ValueSource(strings = {
            "::ffff:127.0.0.1", // loopback
            "::ffff:169.254.169.254", // link-local / cloud metadata endpoint
            "::ffff:10.0.0.5", // RFC1918 private
            "::ffff:192.168.1.1" // RFC1918 private
    })
    void isPrivateOrLoopback_ShouldBlockIpv4MappedPrivateAddresses(String host) throws Exception {
        assertTrue(isPrivateOrLoopback(host),
                host + " is an IPv4-mapped private/loopback address and must be blocked");
    }

    @Test
    void isPrivateOrLoopback_ShouldAllowIpv4MappedPublicAddress() throws Exception {
        // Sanity check the unwrap doesn't over-block: a mapped *public*
        // address must still be allowed through.
        assertFalse(isPrivateOrLoopback("::ffff:8.8.8.8"));
    }

    // ── resolveAndValidate (B-02: DNS-rebinding TOCTOU fix) ──────────
    //
    // The bug this guards against: a prior version validated a hostname via
    // isPrivateOrLoopback(host), then separately called
    // new InetSocketAddress(host, port) to actually connect, which performs
    // its own independent DNS lookup. An attacker's DNS server could return
    // a safe address for the first lookup and a private/internal address
    // for the second. resolveAndValidate() closes that window by resolving
    // once and requiring the caller to connect to the returned InetAddress
    // object directly, never the hostname string again.

    @Test
    void resolveAndValidate_ShouldThrowForLoopbackAddress() {
        assertThrows(SecurityException.class, () -> resolveAndValidate("127.0.0.1"));
    }

    @Test
    void resolveAndValidate_ShouldThrowForLocalhost() {
        assertThrows(SecurityException.class, () -> resolveAndValidate("localhost"));
    }

    @Test
    void resolveAndValidate_ShouldThrowForPrivateAddress() {
        assertThrows(SecurityException.class, () -> resolveAndValidate("192.168.1.1"));
    }

    @Test
    void resolveAndValidate_ShouldThrowForUnresolvableHostFailClosed() {
        assertThrows(SecurityException.class, () -> resolveAndValidate("this-host-does-not-exist.invalid"));
    }

    @Test
    void resolveAndValidate_ShouldReturnResolvedAddressForPublicHost() throws Throwable {
        InetAddress result = resolveAndValidate("8.8.8.8");

        assertNotNull(result);
        assertEquals("8.8.8.8", result.getHostAddress());
    }

    // ── flushBufferedBytes (buffered-request-body-loss fix) ──────────
    //
    // The bug this guards against: header parsing used a BufferedReader,
    // whose readLine() calls can pull far more than just the header lines
    // into its internal buffer in one read (a small request's headers AND
    // body commonly arrive in the same TCP segment). The relay step used to
    // read straight from the socket's raw InputStream afterward, which had
    // already had those extra bytes drained by the reader, silently
    // truncating the forwarded request body.

    @Test
    void flushBufferedBytes_ShouldForwardBytesAlreadyPulledIntoTheReaderBuffer() throws Throwable {
        String simulated = "POST / HTTP/1.1\r\nHost: example.com\r\n\r\nrequest-body-bytes";
        BufferedReader reader = new BufferedReader(new InputStreamReader(
                new ByteArrayInputStream(simulated.getBytes(StandardCharsets.ISO_8859_1)),
                StandardCharsets.ISO_8859_1));

        // Mirror exactly what handleClientConnection/readHeaders do: read
        // the request line, then header lines until the blank separator.
        // Because the whole input is available immediately from a
        // ByteArrayInputStream, BufferedReader's first readLine() call
        // pulls everything — including "request-body-bytes" — into its
        // internal buffer in one shot, deterministically reproducing the
        // scenario that used to silently drop the body.
        reader.readLine();
        String line;
        while ((line = reader.readLine()) != null && !line.isEmpty()) {
            // consume header lines
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        flushBufferedBytes(reader, out);

        assertEquals("request-body-bytes", out.toString(StandardCharsets.ISO_8859_1));
    }

    @Test
    void flushBufferedBytes_ShouldDoNothingWhenNoBytesAreBuffered() throws Throwable {
        BufferedReader reader = new BufferedReader(new InputStreamReader(
                new ByteArrayInputStream(new byte[0]), StandardCharsets.ISO_8859_1));
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        flushBufferedBytes(reader, out);

        assertEquals(0, out.size());
    }

    // ── readHeaders (resource-exhaustion cap) ─────────────────────────

    @Test
    void readHeaders_ShouldRejectRequestsWithTooManyHeaderLines() throws Throwable {
        StringBuilder raw = new StringBuilder();
        for (int i = 0; i < 250; i++) {
            raw.append("X-Header-").append(i).append(": value\r\n");
        }
        raw.append("\r\n");
        BufferedReader reader = new BufferedReader(new InputStreamReader(
                new ByteArrayInputStream(raw.toString().getBytes(StandardCharsets.ISO_8859_1)),
                StandardCharsets.ISO_8859_1));

        assertThrows(java.io.IOException.class, () -> readHeaders(reader));
    }

    @Test
    void readHeaders_ShouldAcceptRequestsWithinTheHeaderLimit() throws Throwable {
        StringBuilder raw = new StringBuilder();
        for (int i = 0; i < 10; i++) {
            raw.append("X-Header-").append(i).append(": value\r\n");
        }
        raw.append("\r\n");
        BufferedReader reader = new BufferedReader(new InputStreamReader(
                new ByteArrayInputStream(raw.toString().getBytes(StandardCharsets.ISO_8859_1)),
                StandardCharsets.ISO_8859_1));

        List<String> headers = readHeaders(reader);

        assertEquals(10, headers.size());
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
