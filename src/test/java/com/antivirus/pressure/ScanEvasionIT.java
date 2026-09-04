package com.antivirus.pressure;

import com.antivirus.service.impl.ThreatIntelSignatureService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.util.ReflectionTestUtils;

import java.net.CookieManager;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Adversarial counterpart to ScanAccuracyIT.
 *
 * ScanAccuracyIT asks "does the engine still fire on the signals it was
 * built to catch". This class asks the opposite, more uncomfortable
 * question: "how easy is it for someone who has read SecurityServiceImpl.java
 * to get a file past those exact signals". Both questions matter and neither
 * substitutes for the other: a detector can hold 100% on its own designed-for
 * corpus while being trivially evadable, and that gap is invisible unless
 * something is actively trying to exploit it.
 *
 * This is not a real-malware test suite. No live payloads are used or
 * committed here; see the class-level note in ScanAccuracyIT and the
 * project README for why that boundary is deliberate. Every case below is a
 * synthetic file engineered to exercise one specific evasion technique
 * against the engine's own published logic (extension checks, regex text
 * patterns, filename substrings, the sliding pattern-scan window), the same
 * category of technique real ransomware/trojan authors use, without any
 * actual malicious code ever existing in this repository.
 *
 * Two things are measured and reported, not one:
 *   - evasionResistanceRate: of the cases DESIGNED to still get caught
 *     despite the evasion attempt (because the underlying detector logic
 *     already accounts for that trick), how many actually were.
 *   - knownBlindSpots: cases that are EXPECTED to slip through given how the
 *     engine is built today. These are not test failures. Pretending they
 *     pass would just hide the gap; the point is to track it explicitly so
 *     it shows up in the same report a reviewer already reads, and so any
 *     future fix shows up here as a case moving from "blind spot" to
 *     "resisted".
 *
 * Named *EvasionIT.java, same convention as *AccuracyIT.java and
 * *PressureIT.java: mvn test never picks this up, only
 * "mvn verify -Ppressure" does.
 *
 * A third test, knownMalwareHashesFromPublicThreatIntelAreDetected(),
 * covers the "use real-world malicious file intelligence" side of this
 * safely: it seeds ThreatIntelSignatureService with a real, publicly
 * published SHA-256 hash of a WannaCry sample (source cited on the method)
 * and proves the lookup and the live scan endpoint both recognize it, using
 * only the hash string, never the actual sample.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("pressuretest")
class ScanEvasionIT {

    @LocalServerPort
    private int port;

    @Autowired
    private ThreatIntelSignatureService threatIntelSignatureService;

    private final ObjectMapper mapper = new ObjectMapper();

    private String baseUrl() {
        return "http://localhost:" + port;
    }

    /**
     * expectCaught = true means this technique is expected to still be
     * flagged (SUSPICIOUS or MALICIOUS) despite the evasion attempt, and a
     * miss counts against evasionResistanceRate. expectCaught = false means
     * this is a documented, currently-known blind spot: the file is
     * expected to come back CLEAN given how the engine works today, and
     * that result is recorded as-is, not asserted against.
     */
    private record EvasionCase(String description, String fileName, byte[] content, boolean expectCaught) {
    }

    /** Same shape, for the false-positive side: legitimate content that must not be over-flagged. */
    private record BenignEdgeCase(String description, String fileName, byte[] content) {
    }

    @Test
    void knownEvasionTechniquesAreTrackedAgainstTheLiveEngine() throws Exception {
        HttpClient client = HttpClient.newBuilder()
                .cookieHandler(new CookieManager())
                .build();

        String username = "pressure_evasion_" + UUID.randomUUID().toString().substring(0, 8);
        String password = "EvasionCorpusPass123!";
        PressureTestAuthSupport.registerAndLogin(client, baseUrl(), username, password);
        String[] csrf = PressureTestAuthSupport.fetchCsrfHeaderAndToken(client, baseUrl()).split("\\|", 2);

        List<EvasionCase> cases = buildEvasionCases();

        int resistExpected = 0;
        int resistActual = 0;
        List<Map<String, Object>> results = new ArrayList<>();
        List<String> newBlindSpots = new ArrayList<>();

        for (EvasionCase c : cases) {
            String verdict = scanOne(client, csrf, c.fileName(), c.content());
            boolean flagged = "MALICIOUS".equals(verdict) || "SUSPICIOUS".equals(verdict);

            if (c.expectCaught()) {
                resistExpected++;
                if (flagged) {
                    resistActual++;
                } else {
                    // A case we believed was covered just slipped through:
                    // this is a real regression, not a known blind spot.
                    newBlindSpots.add(c.description());
                }
            }

            Map<String, Object> row = new LinkedHashMap<>();
            row.put("technique", c.description());
            row.put("expectCaught", c.expectCaught());
            row.put("verdict", verdict);
            row.put("caught", flagged);
            results.add(row);
        }

        double evasionResistanceRate = resistExpected == 0 ? 0.0 : resistActual / (double) resistExpected;

        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("totalTechniques", cases.size());
        metrics.put("expectedCaught", resistExpected);
        metrics.put("actuallyCaught", resistActual);
        metrics.put("evasionResistanceRate", round4(evasionResistanceRate));
        metrics.put("knownBlindSpotCount", (int) cases.stream().filter(c -> !c.expectCaught()).count());
        metrics.put("results", results);
        PressureMetricsCollector.record("evasion", metrics);

        // Only fails if a technique we believed was covered stopped being
        // covered. Documented blind spots (expectCaught = false) never fail
        // this test; that is the whole point of separating the two lists
        // instead of asserting a single accuracy number the way
        // ScanAccuracyIT does.
        assertTrue(newBlindSpots.isEmpty(),
                "Technique(s) previously believed to be caught are now evading detection, "
                        + "this is a real regression, not an expected blind spot: " + newBlindSpots);
    }

    @Test
    void legitimateContentIsNotOverFlagged() throws Exception {
        HttpClient client = HttpClient.newBuilder()
                .cookieHandler(new CookieManager())
                .build();

        String username = "pressure_fp_" + UUID.randomUUID().toString().substring(0, 8);
        String password = "FalsePositivePass123!";
        PressureTestAuthSupport.registerAndLogin(client, baseUrl(), username, password);
        String[] csrf = PressureTestAuthSupport.fetchCsrfHeaderAndToken(client, baseUrl()).split("\\|", 2);

        List<BenignEdgeCase> cases = buildBenignEdgeCases();

        int falsePositives = 0;
        List<Map<String, Object>> results = new ArrayList<>();
        List<String> newFalsePositives = new ArrayList<>();

        for (BenignEdgeCase c : cases) {
            String verdict = scanOne(client, csrf, c.fileName(), c.content());
            boolean flaggedMalicious = "MALICIOUS".equals(verdict);
            if (flaggedMalicious) {
                falsePositives++;
                newFalsePositives.add(c.description());
            }
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("scenario", c.description());
            row.put("verdict", verdict);
            results.add(row);
        }

        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("totalScenarios", cases.size());
        metrics.put("falsePositiveCount", falsePositives);
        metrics.put("falsePositiveRate", round4(falsePositives / (double) cases.size()));
        metrics.put("results", results);
        PressureMetricsCollector.record("falsePositive", metrics);

        // Legitimate sysadmin/dev content landing on MALICIOUS (not merely
        // SUSPICIOUS) is treated as a hard failure: that is the failure mode
        // that erodes user trust in a real product fastest.
        assertTrue(newFalsePositives.isEmpty(),
                "Legitimate content was scored MALICIOUS: " + newFalsePositives);
    }

    /**
     * This is the "real-world malicious files" case handled the safe way.
     *
     * WANNACRY_SHA256 below is a real, publicly published SHA-256 hash of a
     * WannaCry ransomware sample, sourced from MalwareBazaar
     * (bazaar.abuse.ch), which itself cites US-CERT alert TA17-132A
     * (https://www.us-cert.gov/ncas/alerts/TA17-132A). It is only a hash:
     * 64 hex characters, no executable bytes, nothing that can be run,
     * decoded, or reconstructed into the original sample. Publishing a
     * hash of known malware is standard, safe practice, it's exactly what
     * ThreatIntelSignatureService's live MalwareBazaar feed integration
     * already does in production.
     *
     * Part 1 proves the lookup itself works against that real IOC: seed the
     * live bean the same way a background feed refresh would, then confirm
     * isKnownMalicious() recognizes it. Part 2 proves the mechanism is
     * actually wired into the live HTTP scan path end to end, using a
     * second, locally-generated hash (of content this test controls),
     * since matching a real file to an arbitrary pre-published hash would
     * require breaking SHA-256 preimage resistance, not something this test
     * needs or wants to do.
     */
    @Test
    void knownMalwareHashesFromPublicThreatIntelAreDetected() throws Exception {
        // ── Part 1: the exact hash-lookup mechanism, against a real published IOC.
        final String wannaCrySha256 = "6cf273e91bb4a2455f08604ed402d151d39ab528ef9901738c45770097b35ebb";

        assertTrue(seedSignature(wannaCrySha256),
                "Expected the real-world WannaCry IOC hash not to already be present before seeding it");
        assertTrue(threatIntelSignatureService.isKnownMalicious(wannaCrySha256),
                "ThreatIntelSignatureService did not recognize a real, published WannaCry SHA-256 IOC "
                        + "once seeded the same way a live feed refresh would add it");

        // ── Part 2: the same mechanism, proven end to end through the live upload endpoint.
        byte[] controlledContent = ("Synthetic content for ScanEvasionIT's known-hash pathway check, "
                + UUID.randomUUID() + ". Not malware, its hash is added to the signature set below "
                + "purely to exercise the same code path a real IOC hash match would take.")
                .getBytes(StandardCharsets.UTF_8);
        String controlledHash = sha256Hex(controlledContent);
        seedSignature(controlledHash);

        HttpClient client = HttpClient.newBuilder()
                .cookieHandler(new CookieManager())
                .build();
        String username = "pressure_hash_" + UUID.randomUUID().toString().substring(0, 8);
        String password = "HashPathwayPass123!";
        PressureTestAuthSupport.registerAndLogin(client, baseUrl(), username, password);
        String[] csrf = PressureTestAuthSupport.fetchCsrfHeaderAndToken(client, baseUrl()).split("\\|", 2);

        String verdict = scanOne(client, csrf, "known_bad.bin", controlledContent);

        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("realWorldIocSource", "MalwareBazaar (bazaar.abuse.ch), citing US-CERT TA17-132A");
        metrics.put("realWorldIocRecognized", threatIntelSignatureService.isKnownMalicious(wannaCrySha256));
        metrics.put("endToEndHashMatchVerdict", verdict);
        PressureMetricsCollector.record("knownHashPathway", metrics);

        assertEquals("MALICIOUS", verdict,
                "A file whose SHA-256 is present in the threat-intel signature set was not scored "
                        + "MALICIOUS through the live scan endpoint");
    }

    /** Adds a hash to the live bean's signature set the same way a feed refresh would. Returns true if it was new. */
    @SuppressWarnings("unchecked")
    private boolean seedSignature(String sha256Hash) {
        Set<String> signatures = (Set<String>) ReflectionTestUtils.getField(threatIntelSignatureService, "signatures");
        return signatures.add(sha256Hash.toLowerCase(Locale.ROOT));
    }

    private static String sha256Hex(byte[] content) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(content);
        StringBuilder hex = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    private String scanOne(HttpClient client, String[] csrf, String fileName, byte[] content) throws Exception {
        String boundary = "----EvasionITBoundary" + UUID.randomUUID();
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
        return verdictNode.asText();
    }

    private List<EvasionCase> buildEvasionCases() {
        List<EvasionCase> cases = new ArrayList<>();

        // ── Cases the engine's OWN logic already accounts for: expectCaught = true.
        // These are regression guards on protections that already exist.

        // Extension masquerade: a real MZ header behind a claimed .pdf
        // extension. checkExtensionMasquerade() only scores this when the
        // extension is NOT already in SUSPICIOUS_EXTENSIONS (a plain,
        // honestly-named .exe is deliberately never scored here, see the
        // comment on containsSuspiciousBytes()), so this must use a single,
        // non-executable extension to actually exercise the check. Must
        // stay caught.
        byte[] mzHeader = new byte[]{0x4D, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte[] fakePdf = new byte[mzHeader.length + 32];
        System.arraycopy(mzHeader, 0, fakePdf, 0, mzHeader.length);
        cases.add(new EvasionCase(
                "Extension masquerade: invoice.pdf with a real MZ header inside",
                "invoice.pdf", fakePdf, true));

        // Extension case variation: .LOCKED instead of .locked. getExtension()
        // is lowercased before the RANSOMWARE_EXTENSIONS.contains() check, so
        // simple case-shifting should not evade it. Must stay caught.
        cases.add(new EvasionCase(
                "Ransomware extension case variation: .LOCKED instead of .locked",
                "quarterly_report.LOCKED",
                "Uppercase-extension variant of a ransomware-tagged file.".getBytes(StandardCharsets.UTF_8),
                true));

        // ── Cases that exploit gaps the engine does NOT yet cover: expectCaught = false.
        // Documented blind spots, tracked so they show up in every report run.

        // Keyword fragmentation: break the literal token "bitcoin" so the
        // \bbitcoin\b pattern cannot match it, while the sentence still reads
        // as a ransom demand to a human. Deliberately avoids every OTHER
        // literal RANSOMWARE_PATTERNS phrase too (no "your important files",
        // no "ransom", no "btc wallet"), so this genuinely isolates the one
        // technique it claims to test. The scoring engine is pure regex over
        // literal text, so this is expected to evade today.
        cases.add(new EvasionCase(
                "Keyword fragmentation: hyphenating 'bit-coin' to break the ransomware text pattern",
                "payment_instructions.txt",
                ("Access to your data has been restricted. Send funds to our bit-coin wallet "
                        + "address listed on the attached page to restore access.")
                        .getBytes(StandardCharsets.UTF_8),
                false));

        // Base64-encoded payload text: the same ransom note, base64-encoded,
        // so no plaintext trigger phrase ever appears in the scanned bytes.
        // Nothing in the engine currently decodes and re-scans embedded
        // base64 content.
        String ransomNote = "Your files have been encrypted. Contact us with your bitcoin wallet "
                + "payment to receive the decrypt ransom key.";
        cases.add(new EvasionCase(
                "Base64-encoded ransom note: same message, never appears as plaintext",
                "config_backup.dat",
                Base64.getEncoder().encode(ransomNote.getBytes(StandardCharsets.UTF_8)),
                false));

        // Benign filename, malicious-shaped text: TROJAN_NAME_SIGNATURES is a
        // literal substring check against the filename only. Any attacker
        // who does not name their file "backdoor.exe" or "trojan.exe"
        // trivially skips this signal entirely. This is arguably the most
        // realistic blind spot in the whole engine, since no real attacker
        // ships malware with an honest filename.
        cases.add(new EvasionCase(
                "Innocuous filename carrying a real trojan-shaped payload description",
                "quarterly_report_final_v2.txt",
                ("Establishes a reverse connection to the operator's listening socket and "
                        + "relays keystrokes captured via a low-level keyboard hook.")
                        .getBytes(StandardCharsets.UTF_8),
                false));

        // Size-based evasion: content beyond MAX_PATTERN_SCAN_BYTES (10MB) is
        // never read by scanWithPatterns's loop condition at all, so a
        // trigger phrase placed after 10MB of padding is never even
        // examined. This mirrors a real, documented evasion class (AV
        // engines historically capping scan size, and malware authors
        // padding files past that cap).
        int paddingBytes = 10 * 1024 * 1024 + 4096;
        StringBuilder padded = new StringBuilder(paddingBytes + ransomNote.length());
        padded.append("x".repeat(paddingBytes));
        padded.append(ransomNote);
        cases.add(new EvasionCase(
                "Oversized-file evasion: ransom note placed just past the 10MB pattern-scan cap",
                "large_export.txt", padded.toString().getBytes(StandardCharsets.UTF_8), false));

        // Double-extension trick: "invoice.pdf.exe" relies on Windows'
        // default "hide known file extensions" behaviour so a user sees
        // "invoice.pdf" while it is really an .exe, a genuinely common
        // real-world lure. getFileExtension() correctly parses the true
        // last extension (.exe), but SUSPICIOUS_EXTENSIONS.contains(".exe")
        // then makes checkExtensionMasquerade() deliberately skip scoring
        // it (by design, see the comment above that method: an honestly
        // extensioned .exe is never scored there). Nothing else in the
        // engine currently penalizes an honestly-parsed suspicious
        // extension on its own, so this specific social-engineering lure
        // currently scores 0 end to end.
        byte[] doubleExtPayload = new byte[mzHeader.length + 32];
        System.arraycopy(mzHeader, 0, doubleExtPayload, 0, mzHeader.length);
        cases.add(new EvasionCase(
                "Double-extension lure: invoice.pdf.exe, a real MZ header behind Windows' hidden-extension trick",
                "invoice.pdf.exe", doubleExtPayload, false));

        return cases;
    }

    private List<BenignEdgeCase> buildBenignEdgeCases() {
        List<BenignEdgeCase> cases = new ArrayList<>();

        cases.add(new BenignEdgeCase(
                "Real sysadmin script using Runtime.exec and chmod, no malicious intent",
                "deploy_helper.txt",
                ("Deployment note: this build step calls Runtime.exec(\"systemctl restart app\") "
                        + "and runs chmod 777 tmp/ only inside the disposable CI container, never in prod.")
                        .getBytes(StandardCharsets.UTF_8)));

        cases.add(new BenignEdgeCase(
                "Legitimate backup tool documentation mentioning file encryption",
                "backup_tool_readme.txt",
                ("BackupPro automatically calls archive.encrypt() on nightly exports and "
                        + "uploads them via storageClient.upload() to the configured S3 bucket.")
                        .getBytes(StandardCharsets.UTF_8)));

        cases.add(new BenignEdgeCase(
                "Frontend developer notes referencing eval and document.write in a legacy-code writeup",
                "legacy_code_notes.md",
                ("# Legacy widget notes\n\nThe old vendor script still calls eval(userConfig) and "
                        + "document.write(bannerHtml) on load; ticketed for removal next sprint.")
                        .getBytes(StandardCharsets.UTF_8)));

        cases.add(new BenignEdgeCase(
                "Networking sample code opening a plain socket, standard client example",
                "socket_client_example.txt",
                "Example: new Socket(host, port) followed by a standard read/write loop over the stream."
                        .getBytes(StandardCharsets.UTF_8)));

        cases.add(new BenignEdgeCase(
                "IT helpdesk note about registry changes for a printer driver",
                "printer_driver_note.txt",
                "Ran reg add for the printer driver key after the vendor update, resolved the offline queue issue."
                        .getBytes(StandardCharsets.UTF_8)));

        return cases;
    }

    @AfterAll
    static void flushMetrics() {
        PressureMetricsCollector.flush("evasion-metrics.json", "evasion", "falsePositive", "knownHashPathway");
    }

    private static double round4(double value) {
        return Math.round(value * 10000.0) / 10000.0;
    }
}
