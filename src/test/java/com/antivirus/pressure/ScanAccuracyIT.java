package com.antivirus.pressure;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;

import java.net.CookieManager;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Measures detection accuracy against a large synthetic, safely labeled
 * corpus, instead of just checking that a couple of hand-picked files
 * score the way we expect.
 *
 * The corpus is generated in memory at test time, not sourced from any
 * real malware collection: real samples don't belong in this repo or CI.
 * Each "malicious-labeled" sample is built to reliably trip one or more
 * of the actual scoring signals in SecurityServiceImpl (known-hash EICAR
 * match, ransomware extension, ransomware note text, trojan filename
 * signature, rootkit text pattern) so the corpus exercises the real
 * detection code, not a mock of it. Each "benign-labeled" sample is
 * ordinary text with no extension, filename, or content that any
 * detector looks for.
 *
 * A confusion matrix only makes sense as binary, so the three-tier
 * verdict (CLEAN / SUSPICIOUS / MALICIOUS) is collapsed to
 * flagged = SUSPICIOUS or MALICIOUS vs clean = CLEAN. The SUSPICIOUS vs
 * MALICIOUS split among correctly-flagged malicious samples is reported
 * separately as supplementary detail, not blended into the matrix.
 *
 * Named *AccuracyIT.java (not *Test.java), so mvn test never picks this
 * up; only "mvn verify -Ppressure" runs it, same as EndpointPressureIT.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("pressuretest")
class ScanAccuracyIT {

    @LocalServerPort
    private int port;

    private final ObjectMapper mapper = new ObjectMapper();

    // Samples per malicious-labeled category. 6 categories x 850 = 5,100.
    private static final int MALICIOUS_PER_CATEGORY = 850;
    // Samples per benign-labeled category. 4 categories x 1,225 = 4,900.
    private static final int BENIGN_PER_CATEGORY = 1225;
    // Total corpus: 10,000 files. Bumped 10x from the original 1,060-file
    // corpus once the filename-signal bug (see SecurityServiceImpl fix,
    // "evaluate filename-based detection signals against the uploaded
    // display name, not the temp file name") was confirmed and fixed;
    // a larger corpus gives a tighter confidence interval on the accuracy
    // percentage and stresses the scan endpoint harder under concurrency.
    private static final int CONCURRENCY = 24;

    private String baseUrl() {
        return "http://localhost:" + port;
    }

    private record LabeledSample(String fileName, byte[] content, boolean expectFlagged, String category) {
    }

    @Test
    void detectionAccuracyOverSyntheticLabeledCorpusMeetsExpectations() throws Exception {
        HttpClient client = HttpClient.newBuilder()
                .cookieHandler(new CookieManager())
                .build();

        String username = "pressure_accuracy_" + UUID.randomUUID().toString().substring(0, 8);
        String password = "AccuracyCorpusPass123!";
        PressureTestAuthSupport.registerAndLogin(client, baseUrl(), username, password);
        String[] csrf = PressureTestAuthSupport.fetchCsrfHeaderAndToken(client, baseUrl()).split("\\|", 2);

        List<LabeledSample> corpus = buildCorpus();
        assertTrue(corpus.size() >= 10_000,
                "Expected a corpus of at least 10,000 synthetic files, built " + corpus.size());

        ExecutorService pool = Executors.newFixedThreadPool(CONCURRENCY);
        AtomicInteger truePositive = new AtomicInteger(0);
        AtomicInteger falsePositive = new AtomicInteger(0);
        AtomicInteger trueNegative = new AtomicInteger(0);
        AtomicInteger falseNegative = new AtomicInteger(0);
        AtomicInteger scanErrors = new AtomicInteger(0);
        AtomicInteger verdictMalicious = new AtomicInteger(0);
        AtomicInteger verdictSuspicious = new AtomicInteger(0);
        AtomicInteger verdictClean = new AtomicInteger(0);
        // Tier split among malicious-labeled samples the engine actually flagged.
        AtomicInteger flaggedMaliciousAsMalicious = new AtomicInteger(0);
        AtomicInteger flaggedMaliciousAsSuspicious = new AtomicInteger(0);

        List<Callable<Void>> tasks = new ArrayList<>();
        for (LabeledSample sample : corpus) {
            tasks.add(() -> {
                try {
                    String verdict = scanOne(client, csrf, sample);
                    switch (verdict) {
                        case "MALICIOUS" -> verdictMalicious.incrementAndGet();
                        case "SUSPICIOUS" -> verdictSuspicious.incrementAndGet();
                        default -> verdictClean.incrementAndGet();
                    }
                    boolean flagged = "MALICIOUS".equals(verdict) || "SUSPICIOUS".equals(verdict);
                    if (sample.expectFlagged() && flagged) {
                        truePositive.incrementAndGet();
                        if ("MALICIOUS".equals(verdict)) {
                            flaggedMaliciousAsMalicious.incrementAndGet();
                        } else {
                            flaggedMaliciousAsSuspicious.incrementAndGet();
                        }
                    } else if (sample.expectFlagged()) {
                        falseNegative.incrementAndGet();
                    } else if (flagged) {
                        falsePositive.incrementAndGet();
                    } else {
                        trueNegative.incrementAndGet();
                    }
                } catch (Exception ex) {
                    scanErrors.incrementAndGet();
                }
                return null;
            });
        }

        pool.invokeAll(tasks, 30, TimeUnit.MINUTES);
        pool.shutdown();

        int tp = truePositive.get();
        int fp = falsePositive.get();
        int tn = trueNegative.get();
        int fn = falseNegative.get();
        int totalScored = tp + fp + tn + fn;

        double accuracy = totalScored == 0 ? 0.0 : (tp + tn) / (double) totalScored;
        double precision = (tp + fp) == 0 ? 0.0 : tp / (double) (tp + fp);
        double recall = (tp + fn) == 0 ? 0.0 : tp / (double) (tp + fn);
        double f1 = (precision + recall) == 0 ? 0.0 : 2 * precision * recall / (precision + recall);

        Map<String, Object> confusionMatrix = new LinkedHashMap<>();
        confusionMatrix.put("truePositive", tp);
        confusionMatrix.put("falsePositive", fp);
        confusionMatrix.put("trueNegative", tn);
        confusionMatrix.put("falseNegative", fn);

        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("totalFiles", corpus.size());
        metrics.put("scanErrors", scanErrors.get());
        metrics.put("confusionMatrix", confusionMatrix);
        metrics.put("accuracy", round4(accuracy));
        metrics.put("precision", round4(precision));
        metrics.put("recall", round4(recall));
        metrics.put("f1", round4(f1));
        metrics.put("verdictBreakdown", Map.of(
                "MALICIOUS", verdictMalicious.get(),
                "SUSPICIOUS", verdictSuspicious.get(),
                "CLEAN", verdictClean.get()));
        metrics.put("maliciousLabeledTierSplit", Map.of(
                "detectedAsMalicious", flaggedMaliciousAsMalicious.get(),
                "detectedAsSuspicious", flaggedMaliciousAsSuspicious.get()));
        PressureMetricsCollector.record("accuracy", metrics);

        assertTrue(scanErrors.get() < corpus.size() * 0.01,
                "Too many scan requests failed outright (" + scanErrors.get() + "/" + corpus.size()
                        + "); accuracy numbers are not trustworthy until the transport itself is stable");
        // A loose floor, not a strict SLA: this test exists to catch the
        // detection engine regressing on its own designed-for signals, not
        // to gate merges on a specific accuracy target creeping up or down.
        assertTrue(accuracy > 0.9,
                "Accuracy over the synthetic corpus was " + accuracy
                        + ", expected the engine to correctly classify over 90% of "
                        + "samples specifically designed to trip or avoid its own signals");
    }

    private String scanOne(HttpClient client, String[] csrf, LabeledSample sample) throws Exception {
        String boundary = "----AccuracyITBoundary" + UUID.randomUUID();
        byte[] head = ("--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"file\"; filename=\"" + sample.fileName() + "\"\r\n"
                + "Content-Type: application/octet-stream\r\n\r\n").getBytes(StandardCharsets.UTF_8);
        byte[] tail = ("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8);
        byte[] multipartBody = new byte[head.length + sample.content().length + tail.length];
        System.arraycopy(head, 0, multipartBody, 0, head.length);
        System.arraycopy(sample.content(), 0, multipartBody, head.length, sample.content().length);
        System.arraycopy(tail, 0, multipartBody, head.length + sample.content().length, tail.length);

        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl() + "/api/antivirus/scan/file"))
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .header(csrf[0], csrf[1])
                .POST(BodyPublishers.ofByteArray(multipartBody))
                .build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) {
            throw new IllegalStateException("Scan of " + sample.fileName() + " (" + sample.category()
                    + ") returned HTTP " + resp.statusCode());
        }
        JsonNode body = mapper.readTree(resp.body());
        JsonNode verdictNode = body.get("verdict");
        if (verdictNode == null || verdictNode.isNull()) {
            throw new IllegalStateException("Scan response for " + sample.fileName() + " had no verdict field");
        }
        return verdictNode.asText();
    }

    /**
     * Builds the labeled corpus. Malicious-labeled categories are chosen to
     * each reliably cross THRESHOLD_SUSPICIOUS (25) on their own in
     * SecurityServiceImpl's scoring engine (see that class for the exact
     * per-signal weights); benign-labeled categories contain nothing any
     * detector looks for.
     */
    private List<LabeledSample> buildCorpus() {
        List<LabeledSample> corpus = new ArrayList<>();

        // EICAR standard test string. score = 100 (known-hash match) -> MALICIOUS.
        // Safe by design: this is the industry-standard antivirus test file,
        // not real malware, recognized and expected by every scanner.
        String eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        for (int i = 0; i < MALICIOUS_PER_CATEGORY; i++) {
            corpus.add(new LabeledSample("eicar_test_" + i + ".txt",
                    eicar.getBytes(StandardCharsets.UTF_8), true, "eicar"));
        }

        // Ransomware extension alone. score = 60 -> MALICIOUS.
        for (int i = 0; i < MALICIOUS_PER_CATEGORY; i++) {
            String content = "Sample file body " + i + " for ransomware-extension category.\n";
            corpus.add(new LabeledSample("archive_backup_" + i + ".locked",
                    content.getBytes(StandardCharsets.UTF_8), true, "ransomware_extension"));
        }

        // Ransomware note text pattern alone. score = 45 -> SUSPICIOUS.
        for (int i = 0; i < MALICIOUS_PER_CATEGORY; i++) {
            String content = "NOTICE #" + i + "\nYour important files have been encrypted. "
                    + "Contact us for the decrypt ransom payment instructions.\n";
            corpus.add(new LabeledSample("readme_notice_" + i + ".txt",
                    content.getBytes(StandardCharsets.UTF_8), true, "ransomware_note_text"));
        }

        // Ransomware note text + trojan filename signature. score = 45+35 = 80 -> MALICIOUS.
        for (int i = 0; i < MALICIOUS_PER_CATEGORY; i++) {
            String content = "Your files have been encrypted. Send payment to our bitcoin wallet #" + i + ".\n";
            corpus.add(new LabeledSample("backdoor_payload_" + i + ".txt",
                    content.getBytes(StandardCharsets.UTF_8), true, "ransomware_text_plus_trojan_name"));
        }

        // Trojan filename signature alone. score = 35 -> SUSPICIOUS.
        for (int i = 0; i < MALICIOUS_PER_CATEGORY; i++) {
            String content = "Utility script #" + i + ", nothing unusual in the body text.\n";
            corpus.add(new LabeledSample("remote_access_tool_" + i + ".txt",
                    content.getBytes(StandardCharsets.UTF_8), true, "trojan_name_only"));
        }

        // Rootkit kernel-manipulation text pattern + trojan filename signature.
        // score = 20+35 = 55 -> SUSPICIOUS.
        for (int i = 0; i < MALICIOUS_PER_CATEGORY; i++) {
            String content = "Module notes #" + i + ": installs a syscall table hook for process hiding.\n"
                    + "trojan reference in body text for good measure.\n";
            corpus.add(new LabeledSample("stealer_module_notes_" + i + ".txt",
                    content.getBytes(StandardCharsets.UTF_8), true, "rootkit_text_plus_trojan_name"));
        }

        // Benign: plain prose, no suspicious extension, filename, or content.
        for (int i = 0; i < BENIGN_PER_CATEGORY; i++) {
            String content = "Weekly status note " + i + ". Nothing to report, project is on schedule "
                    + "and the team met all planned milestones this sprint.\n";
            corpus.add(new LabeledSample("status_note_" + i + ".txt",
                    content.getBytes(StandardCharsets.UTF_8), false, "benign_prose"));
        }

        // Benign: CSV-style tabular data.
        for (int i = 0; i < BENIGN_PER_CATEGORY; i++) {
            StringBuilder csv = new StringBuilder("id,name,quantity,price\n");
            for (int row = 0; row < 5; row++) {
                csv.append(i).append(row).append(",item-").append(row).append(",")
                        .append(row + 1).append(",").append((row + 1) * 9.5).append("\n");
            }
            corpus.add(new LabeledSample("inventory_export_" + i + ".csv",
                    csv.toString().getBytes(StandardCharsets.UTF_8), false, "benign_csv"));
        }

        // Benign: JSON-style config content.
        for (int i = 0; i < BENIGN_PER_CATEGORY; i++) {
            String json = "{\n  \"id\": " + i + ",\n  \"environment\": \"staging\",\n"
                    + "  \"featureFlags\": {\"betaDashboard\": false, \"newOnboarding\": true}\n}\n";
            corpus.add(new LabeledSample("app_config_" + i + ".json",
                    json.getBytes(StandardCharsets.UTF_8), false, "benign_json"));
        }

        // Benign: markdown-style notes.
        for (int i = 0; i < BENIGN_PER_CATEGORY; i++) {
            String md = "# Meeting notes " + i + "\n\n- Reviewed roadmap\n- Agreed on next milestones\n"
                    + "- No blockers reported\n";
            corpus.add(new LabeledSample("meeting_notes_" + i + ".md",
                    md.getBytes(StandardCharsets.UTF_8), false, "benign_markdown"));
        }

        return corpus;
    }

    @AfterAll
    static void flushMetrics() {
        PressureMetricsCollector.flush("accuracy-metrics.json", "accuracy");
    }

    private static double round4(double value) {
        return Math.round(value * 10000.0) / 10000.0;
    }
}
