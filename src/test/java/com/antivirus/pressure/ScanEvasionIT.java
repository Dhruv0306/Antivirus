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
 * safely: it seeds ThreatIntelSignatureService with real, publicly
 * published SHA-256 hashes spanning multiple distinct, cited malware
 * families (WannaCry, NotPetya) and proves the lookup and the live scan
 * endpoint both recognize them, using only hash strings, never actual
 * samples.
 *
 * A fourth test, knownGoodOpenSourceArchivesAreNeverFlaggedAsMalicious(),
 * is that test's false-positive counterpart: real, unmodified GitHub tag
 * source archives for well-known open-source projects (jq, ripgrep,
 * shellcheck, see src/test/resources/known-good-samples/PROVENANCE.md for
 * exact provenance and reproduction commands), scanned under both an
 * honest and a deliberately adversarial filename, confirming genuinely
 * legitimate software is never convicted outright regardless of what it's
 * named.
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
     * Each hash below is real, published SHA-256 IOC data for a distinct,
     * well-documented malware family, not a single sample. They are only
     * hashes: 64 hex characters each, no executable bytes, nothing that can
     * be run, decoded, or reconstructed into the original sample. Publishing
     * hashes of known malware is standard, safe practice, it's exactly what
     * ThreatIntelSignatureService's live MalwareBazaar feed integration
     * already does in production. Sources are cited per entry in
     * KNOWN_MALWARE_IOCS below.
     *
     * Part 1 proves the lookup itself works against real IOCs, across
     * multiple distinct families, not just one: seed the live bean the same
     * way a background feed refresh would, then confirm isKnownMalicious()
     * recognizes each one, and report per-family coverage rather than a
     * single overall boolean. Part 2 proves the mechanism is actually wired
     * into the live HTTP scan path end to end, using a second,
     * locally-generated hash (of content this test controls), since
     * matching a real file to an arbitrary pre-published hash would require
     * breaking SHA-256 preimage resistance, not something this test needs or
     * wants to do.
     */
    private record KnownMalwareIoc(String family, String sha256, String citation) {
    }

    private static final List<KnownMalwareIoc> KNOWN_MALWARE_IOCS = List.of(
            new KnownMalwareIoc(
                    "WannaCry",
                    "6cf273e91bb4a2455f08604ed402d151d39ab528ef9901738c45770097b35ebb",
                    "MalwareBazaar (bazaar.abuse.ch), citing US-CERT TA17-132A"),
            new KnownMalwareIoc(
                    "NotPetya",
                    "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745",
                    "Main payload DLL hash, cross-referenced across Hitachi HIRT-PUB17010, "
                            + "Barracuda Networks research, and CISA/US-CERT TA17-181A"));

    @SuppressWarnings("null")
@Test
    void knownMalwareHashesFromPublicThreatIntelAreDetected() throws Exception {
        // ── Part 1: the exact hash-lookup mechanism, against real published IOCs across multiple families.
        Map<String, Boolean> perFamilyRecognized = new LinkedHashMap<>();
        for (KnownMalwareIoc ioc : KNOWN_MALWARE_IOCS) {
            assertTrue(seedSignature(ioc.sha256()),
                    "Expected the real-world " + ioc.family() + " IOC hash not to already be present "
                            + "before seeding it");
            boolean recognized = threatIntelSignatureService.isKnownMalicious(ioc.sha256());
            perFamilyRecognized.put(ioc.family(), recognized);
            assertTrue(recognized,
                    "ThreatIntelSignatureService did not recognize a real, published " + ioc.family()
                            + " SHA-256 IOC (" + ioc.citation() + ") once seeded the same way a live "
                            + "feed refresh would add it");
        }

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

        long recognizedCount = perFamilyRecognized.values().stream().filter(Boolean::booleanValue).count();
        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("familiesCovered", KNOWN_MALWARE_IOCS.size());
        metrics.put("familiesRecognized", recognizedCount);
        metrics.put("knownHashCoverageByFamily", perFamilyRecognized);
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

    /**
     * Phase 2's false-positive counterpart to the Phase 1 known-hash test above.
     *
     * Each entry is the exact, unmodified GitHub tag source archive for a real,
     * well-known open-source project (jq, ripgrep, shellcheck), fetched directly
     * from codeload.github.com, never a synthetic stand-in. Full provenance,
     * exact download command, and expected SHA-256 for independent verification
     * live in src/test/resources/known-good-samples/PROVENANCE.md.
     *
     * Each archive is scanned twice: once under its own honest filename, and
     * once under a deliberately adversarial filename containing a literal
     * TROJAN_NAME_SIGNATURES substring ("backdoor"). The honest-filename case
     * is expected to come back CLEAN. The adversarial-filename case is allowed
     * to come back SUSPICIOUS, since SCORE_TROJAN_NAME (35) crossing
     * THRESHOLD_SUSPICIOUS (25) but not THRESHOLD_MALICIOUS (60) on a
     * suspicious filename alone is the engine's calibration working as
     * intended, flagging for review rather than convicting outright. Neither
     * case may come back MALICIOUS: real, unmodified, popular open-source
     * software must never be convicted outright by this engine, regardless of
     * what it happens to be named.
     */
    private record KnownGoodArchive(String resourceName, String honestFileName, String expectedSha256) {
    }

    private static final List<KnownGoodArchive> KNOWN_GOOD_ARCHIVES = List.of(
            new KnownGoodArchive("jq-1.7.1.tar.gz", "jq-1.7.1.tar.gz",
                    "fc75b1824aba7a954ef0886371d951c3bf4b6e0a921d1aefc553f309702d6ed1"),
            new KnownGoodArchive("ripgrep-14.1.0.tar.gz", "ripgrep-14.1.0.tar.gz",
                    "33c6169596a6bbfdc81415910008f26e0809422fda2d849562637996553b2ab6"),
            new KnownGoodArchive("shellcheck-0.10.0.tar.gz", "shellcheck-0.10.0.tar.gz",
                    "149ef8f90c0ccb8a5a9e64d2b8cdd079ac29f7d2f5a263ba64087093e9135050"));

    @Test
    void knownGoodOpenSourceArchivesAreNeverFlaggedAsMalicious() throws Exception {
        HttpClient client = HttpClient.newBuilder()
                .cookieHandler(new CookieManager())
                .build();
        String username = "pressure_knowngood_" + UUID.randomUUID().toString().substring(0, 8);
        String password = "KnownGoodArchivePass123!";
        PressureTestAuthSupport.registerAndLogin(client, baseUrl(), username, password);
        String[] csrf = PressureTestAuthSupport.fetchCsrfHeaderAndToken(client, baseUrl()).split("\\|", 2);

        List<Map<String, Object>> results = new ArrayList<>();
        List<String> falsePositives = new ArrayList<>();

        for (KnownGoodArchive archive : KNOWN_GOOD_ARCHIVES) {
            byte[] content = readClasspathResource("known-good-samples/" + archive.resourceName());
            String actualHash = sha256Hex(content);
            assertEquals(archive.expectedSha256(), actualHash,
                    "Fixture " + archive.resourceName() + " does not match its pinned SHA-256, see "
                            + "PROVENANCE.md, either the fixture was replaced or corrupted");

            String honestVerdict = scanOne(client, csrf, archive.honestFileName(), content);
            String adversarialFileName = "backdoor_" + archive.honestFileName();
            String adversarialVerdict = scanOne(client, csrf, adversarialFileName, content);

            if ("MALICIOUS".equals(honestVerdict)) {
                falsePositives.add(archive.honestFileName() + " (honest filename)");
            }
            if ("MALICIOUS".equals(adversarialVerdict)) {
                falsePositives.add(adversarialFileName + " (adversarial filename)");
            }

            Map<String, Object> row = new LinkedHashMap<>();
            row.put("archive", archive.honestFileName());
            row.put("honestFilenameVerdict", honestVerdict);
            row.put("adversarialFilenameVerdict", adversarialVerdict);
            results.add(row);
        }

        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("archivesChecked", KNOWN_GOOD_ARCHIVES.size());
        metrics.put("falsePositiveCount", falsePositives.size());
        metrics.put("results", results);
        PressureMetricsCollector.record("knownGoodArchive", metrics);

        assertTrue(falsePositives.isEmpty(),
                "Real, unmodified open-source archives were scored MALICIOUS: " + falsePositives);
    }

    private static byte[] readClasspathResource(String resourcePath) throws Exception {
        try (var in = ScanEvasionIT.class.getClassLoader().getResourceAsStream(resourcePath)) {
            if (in == null) {
                throw new IllegalStateException("Test resource not found on classpath: " + resourcePath);
            }
            return in.readAllBytes();
        }
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
        PressureMetricsCollector.flush("evasion-metrics.json", "evasion", "falsePositive",
                "knownHashPathway", "knownGoodArchive");
    }

    private static double round4(double value) {
        return Math.round(value * 10000.0) / 10000.0;
    }
}
