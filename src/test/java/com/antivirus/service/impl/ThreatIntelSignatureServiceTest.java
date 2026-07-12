package com.antivirus.service.impl;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for ThreatIntelSignatureService. HttpClient is mocked
 * throughout, this suite makes zero real network calls, unlike the
 * previous static-initializer version of this logic which fired an actual
 * HTTP request the moment the class was loaded by any test in the module.
 */
@ExtendWith(MockitoExtension.class)
class ThreatIntelSignatureServiceTest {

    @Mock
    private HttpClient httpClient;

    private ThreatIntelSignatureService service;

    @TempDir
    Path tempDir;

    private Path cacheFile;

    @BeforeEach
    void setUp() {
        service = new ThreatIntelSignatureService();
        ReflectionTestUtils.setField(service, "threatIntelHttpClient", httpClient);
        ReflectionTestUtils.setField(service, "feedUrlsConfig", "https://example.invalid/feed.txt");
        cacheFile = tempDir.resolve("cache.sha256");
        ReflectionTestUtils.setField(service, "cacheFileConfig", cacheFile.toString());
        ReflectionTestUtils.setField(service, "refreshOnStartup", false);
        ReflectionTestUtils.setField(service, "enabled", true);
    }

    @AfterEach
    void tearDown() {
        service.shutdown();
    }

    // ── init() ──────────────────────────────────────────────────────

    @Test
    void init_ShouldSeedEicarSignatureEvenWhenDisabled() {
        ReflectionTestUtils.setField(service, "enabled", false);

        service.init();

        assertTrue(service.isKnownMalicious(ThreatIntelSignatureService.EICAR_SHA256));
        assertEquals(1, service.signatureCount());
        verifyNoInteractions(httpClient);
    }

    @SuppressWarnings("unchecked")
    @Test
    void init_ShouldNotBlockOnNetworkCallForStartup() throws Exception {
        lenient().when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> {
                    Thread.sleep(2000);
                    throw new IOException("simulated timeout");
                });

        long start = System.nanoTime();
        service.init();
        long elapsedMillis = (System.nanoTime() - start) / 1_000_000;

        assertTrue(elapsedMillis < 500,
                "init() should return immediately; took " + elapsedMillis + "ms");
    }

    // ── refreshFromRemote() ─────────────────────────────────────────

    @Test
    void refreshFromRemote_ShouldAddSignaturesFromSuccessfulFeed() throws Exception {
        String feedBody = "# comment line, not a hash\n"
                + "2f081ff5029565aef3c185f676430418a54b114bf75c640dd858e4d38f12de02\n"
                + "4db73769880dde1f532aa8fcdc2f9790fecb914ea1b77a863fe374a3a579fd47\n";
        stubFeedResponse(200, feedBody);

        int count = service.refreshFromRemote();

        assertEquals(2, count);
        assertTrue(service.isKnownMalicious("2f081ff5029565aef3c185f676430418a54b114bf75c640dd858e4d38f12de02"));
        assertTrue(service.isKnownMalicious("4DB73769880DDE1F532AA8FCDC2F9790FECB914EA1B77A863FE374A3A579FD47"));
    }

    @Test
    void refreshFromRemote_ShouldIgnoreNonSuccessStatusCode() throws Exception {
        stubFeedResponse(503, "Service Unavailable");

        int count = service.refreshFromRemote();

        assertEquals(0, count);
    }

    @SuppressWarnings("unchecked")
    @Test
    void refreshFromRemote_ShouldToleratesNetworkFailureWithoutThrowing() throws Exception {
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new IOException("connection refused"));

        assertDoesNotThrow(() -> service.refreshFromRemote());
    }

    @Test
    void refreshFromRemote_ShouldPersistFetchedSignaturesToCache() throws Exception {
        stubFeedResponse(200, "818ed536a50e205f6ef036a109c847869ff78100e87ceae800f5c43d62bb26bd\n");

        service.refreshFromRemote();

        assertTrue(Files.isRegularFile(cacheFile));
        List<String> lines = Files.readAllLines(cacheFile);
        assertTrue(lines.contains("818ed536a50e205f6ef036a109c847869ff78100e87ceae800f5c43d62bb26bd"));
    }

    // ── extractSha256Signatures() ───────────────────────────────────

    @Test
    void extractSha256Signatures_ShouldFindHashesAndIgnoreShortTokens() {
        String content = "sha256_hash\n"
                + "2f081ff5029565aef3c185f676430418a54b114bf75c640dd858e4d38f12de02\n"
                + "not-a-hash\n"
                + "12345\n";

        Set<String> found = ThreatIntelSignatureService.extractSha256Signatures(content);

        assertEquals(1, found.size());
        assertTrue(found.contains("2f081ff5029565aef3c185f676430418a54b114bf75c640dd858e4d38f12de02"));
    }

    @Test
    void extractSha256Signatures_ShouldReturnEmptySetForBlankInput() {
        assertTrue(ThreatIntelSignatureService.extractSha256Signatures("").isEmpty());
        assertTrue(ThreatIntelSignatureService.extractSha256Signatures(null).isEmpty());
    }

    // ── isKnownMalicious() ──────────────────────────────────────────

    @Test
    void isKnownMalicious_ShouldReturnFalseForNullOrUnknownHash() {
        assertFalse(service.isKnownMalicious(null));
        assertFalse(service.isKnownMalicious("deadbeef"));
    }

    // ── helpers ──────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    private void stubFeedResponse(int statusCode, String body) throws Exception {
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(statusCode);
        lenient().when(response.body()).thenReturn(body);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(response);
    }
}