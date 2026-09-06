package com.antivirus.pressure;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;

import java.io.IOException;
import java.net.CookieManager;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase 5: the one phase in the real-world-testing plan that changes what
 * the engine can actually detect, rather than widening test coverage around
 * detection that already exists. Every prior phase strengthened confidence
 * in a fundamentally string/extension/hash-based engine. That kind of
 * engine structurally cannot see packed or encrypted executables, since
 * packing is specifically designed to defeat static string matching, and
 * packed malware represents the overwhelming majority of real-world
 * samples. SecurityServiceImpl now computes Shannon entropy over files that
 * already look executable (by extension or by real header bytes) and scores
 * high entropy as its own signal (HIGH_ENTROPY_EXECUTABLE), see the
 * constant block near ENTROPY_SAMPLE_BYTES in SecurityServiceImpl for the
 * full calibration rationale.
 *
 * Two complementary validation strategies, not one:
 *
 * 1. Portable, synthetic, always runs, no external tool dependency.
 *    SecureRandom bytes have a provably near-maximal Shannon entropy (close
 *    to 8.0 bits/byte), making them a simple, deterministic, correctness
 *    guaranteed stand-in for "packed or encrypted content" without needing
 *    to actually pack anything. These tests validate the entropy math
 *    itself and, just as importantly, the executable-like gating decision:
 *    that a non-executable file with the exact same random bytes is NOT
 *    flagged, which is what keeps this signal from becoming a
 *    false-positive machine against every legitimate zip, JPEG, or
 *    already-encrypted backup on the system.
 *
 * 2. Real-world, conditional, richer signal when available.
 *    UPX-packs an actual small system ELF binary (/bin/true, present on
 *    every Linux runner this suite runs on) at test time and confirms
 *    entropy fires on the packed output but not the unpacked original.
 *    This is real packed-executable behavior, not a synthetic stand-in, but
 *    it depends on the `upx` tool being present, so it uses
 *    Assumptions.assumeTrue() to skip gracefully (not fail) when upx isn't
 *    installed, rather than making local development depend on a system
 *    package. The project's own CI (.github/workflows/pressure-test.yml)
 *    installs upx-ucl specifically so this richer test actually runs there.
 *
 * Named *EntropyDetectionIT.java, its own include pattern in pom.xml's
 * pressure profile (**&#47;*EntropyDetectionIT.java), same convention as the
 * other *IT.java pressure-suite classes: mvn test never picks this up, only
 * "mvn verify -Ppressure" does.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("pressuretest")
class EntropyDetectionIT {

    @LocalServerPort
    private int port;

    private final ObjectMapper mapper = new ObjectMapper();

    private String baseUrl() {
        return "http://localhost:" + port;
    }

    private record ScanOutcome(String verdict, String detectionSignals) {
        boolean hasHighEntropySignal() {
            return detectionSignals != null && detectionSignals.contains("HIGH_ENTROPY_EXECUTABLE");
        }
    }

    @Test
    void highEntropyContentUnderExecutableExtensionIsFlaggedSuspicious() throws Exception {
        byte[] highEntropyContent = randomBytes(256 * 1024);

        ScanOutcome outcome = scanAsNewUser("entropy_exec_", "installer.exe", highEntropyContent);

        assertEquals("SUSPICIOUS", outcome.verdict(),
                "256KB of cryptographically random bytes under a .exe extension should score exactly "
                        + "SCORE_HIGH_ENTROPY, crossing THRESHOLD_SUSPICIOUS but not THRESHOLD_MALICIOUS "
                        + "on its own");
        assertTrue(outcome.hasHighEntropySignal(),
                "Expected HIGH_ENTROPY_EXECUTABLE in detectionSignals for high-entropy content under a "
                        + "recognized executable extension");
    }

    @Test
    void sameHighEntropyContentUnderNonExecutableExtensionIsNotFlagged() throws Exception {
        byte[] highEntropyContent = randomBytes(256 * 1024);

        ScanOutcome outcome = scanAsNewUser("entropy_nonexec_", "archive.zip", highEntropyContent);

        assertFalse(outcome.hasHighEntropySignal(),
                "The exact same high-entropy bytes under a .zip extension (not executable-like by "
                        + "extension, and random bytes are not going to coincidentally start with an MZ or "
                        + "ELF header) must not be entropy-scored. This is the mitigation for the "
                        + "well-known entropy-detection false-positive mode: ordinary compressed and "
                        + "encrypted files are naturally high-entropy and completely legitimate.");
        assertEquals("CLEAN", outcome.verdict());
    }

    @Test
    void lowEntropyContentUnderExecutableExtensionIsNotFlaggedForEntropyAlone() throws Exception {
        String plainText = "This is an ordinary plaintext status log line, repeated many times over. "
                .repeat(2000);

        ScanOutcome outcome = scanAsNewUser("entropy_lowent_", "status_tool.exe",
                plainText.getBytes(StandardCharsets.UTF_8));

        assertFalse(outcome.hasHighEntropySignal(),
                "Plaintext content (roughly 4.0-4.5 bits/byte) under a .exe extension is exactly the "
                        + "case that must NOT trigger entropy scoring, an honest, uncompressed executable "
                        + "should never be penalized just for having a suspicious extension");
    }

    @SuppressWarnings("null")
    @Test
    void realUpxPackedBinaryIsFlaggedByEntropyWhenUpxIsAvailable(@TempDir Path tempDir) throws Exception {
        Assumptions.assumeTrue(isUpxAvailable(), "upx not found on PATH, skipping real-packer validation");
        Path sourceBinary = locateRealBinary();
        Assumptions.assumeTrue(sourceBinary != null, "No known small system binary found to pack, skipping");

        byte[] unpackedBytes = Files.readAllBytes(sourceBinary);
        Path packedPath = tempDir.resolve("packed.bin");
        boolean packed = tryUpxPack(sourceBinary, packedPath);
        Assumptions.assumeTrue(packed, "upx declined to pack " + sourceBinary + ", skipping");
        byte[] packedBytes = Files.readAllBytes(packedPath);

        // .dat, not .exe/.bin: deliberately NOT in SUSPICIOUS_EXTENSIONS, so
        // a positive result here proves detection via the real ELF header
        // bytes alone (containsSuspiciousBytes), not via the extension.
        ScanOutcome unpackedOutcome = scanAsNewUser("entropy_upx_plain_", "sample.dat", unpackedBytes);
        ScanOutcome packedOutcome = scanAsNewUser("entropy_upx_packed_", "sample.dat", packedBytes);

        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("upxAvailable", true);
        metrics.put("sourceBinary", sourceBinary.toString());
        metrics.put("unpackedHasEntropySignal", unpackedOutcome.hasHighEntropySignal());
        metrics.put("packedHasEntropySignal", packedOutcome.hasHighEntropySignal());
        metrics.put("packedVerdict", packedOutcome.verdict());
        PressureMetricsCollector.record("entropyDetection", metrics);

        assertFalse(unpackedOutcome.hasHighEntropySignal(),
                "The unpacked source binary should not trip the entropy signal, real, ordinary compiled "
                        + "code sits well below the packed/encrypted entropy band");
        assertTrue(packedOutcome.hasHighEntropySignal(),
                "The UPX-packed version of the exact same binary, identified purely by its real ELF "
                        + "header bytes under a non-executable .dat extension, should trip the entropy "
                        + "signal");
    }

    private static byte[] randomBytes(int count) {
        byte[] data = new byte[count];
        new SecureRandom().nextBytes(data);
        return data;
    }

    private static boolean isUpxAvailable() {
        try {
            Process p = new ProcessBuilder("upx", "--version").redirectErrorStream(true).start();
            return p.waitFor() == 0;
        } catch (IOException | InterruptedException e) {
            return false;
        }
    }

    private static Path locateRealBinary() {
        for (String candidate : new String[]{"/bin/true", "/usr/bin/true"}) {
            Path path = Path.of(candidate);
            if (Files.isRegularFile(path)) {
                return path;
            }
        }
        return null;
    }

    private static boolean tryUpxPack(Path source, Path destination) {
        try {
            Process p = new ProcessBuilder("upx", "--best", "-o", destination.toString(), source.toString())
                    .redirectErrorStream(true)
                    .start();
            int exit = p.waitFor();
            return exit == 0 && Files.isRegularFile(destination) && Files.size(destination) > 0;
        } catch (IOException | InterruptedException e) {
            return false;
        }
    }

    private ScanOutcome scanAsNewUser(String usernamePrefix, String fileName, byte[] content) throws Exception {
        HttpClient client = HttpClient.newBuilder()
                .cookieHandler(new CookieManager())
                .build();
        String username = usernamePrefix + UUID.randomUUID().toString().substring(0, 8);
        String password = "EntropyDetectionPass123!";
        PressureTestAuthSupport.registerAndLogin(client, baseUrl(), username, password);
        String[] csrf = PressureTestAuthSupport.fetchCsrfHeaderAndToken(client, baseUrl()).split("\\|", 2);
        return scanOne(client, csrf, fileName, content);
    }

    private ScanOutcome scanOne(HttpClient client, String[] csrf, String fileName, byte[] content) throws Exception {
        String boundary = "----EntropyDetectionITBoundary" + UUID.randomUUID();
        byte[] head = ("--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"file\"; filename=\"" + fileName + "\"\r\n"
                + "Content-Type: application/octet-stream\r\n\r\n").getBytes(StandardCharsets.UTF_8);
        byte[] tail = ("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8);
        byte[] multipartBody = new byte[head.length + content.length + tail.length];
        System.arraycopy(head, 0, multipartBody, 0, head.length);
        System.arraycopy(content, 0, multipartBody, head.length, content.length);
        System.arraycopy(tail, 0, multipartBody, head.length + content.length, tail.length);

        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl() + "/api/antivirus/scan/file"))
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .header(csrf[0], csrf[1])
                .POST(BodyPublishers.ofByteArray(multipartBody))
                .build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) {
            throw new IllegalStateException("Scan of " + fileName + " returned HTTP " + resp.statusCode());
        }
        JsonNode body = mapper.readTree(resp.body());
        JsonNode verdictNode = body.get("verdict");
        if (verdictNode == null || verdictNode.isNull()) {
            throw new IllegalStateException("Scan response for " + fileName + " had no verdict field");
        }
        JsonNode signalsNode = body.get("detectionSignals");
        String signals = (signalsNode == null || signalsNode.isNull()) ? null : signalsNode.asText();
        return new ScanOutcome(verdictNode.asText(), signals);
    }

    @AfterAll
    static void flushMetrics() {
        PressureMetricsCollector.flush("entropy-metrics.json", "entropyDetection");
    }
}
